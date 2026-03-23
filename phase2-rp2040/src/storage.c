/**
 * Flash storage — persists master secret and sign counter across reboots.
 *
 * Uses the last 4KB sector of flash. Layout:
 *
 *   Bytes 0-3:      Magic (0xF1D0F1D0) — marks a valid storage sector
 *   Bytes 4-35:     Master secret (32 bytes)
 *   Bytes 36-39:    Padding (0xFF)
 *   Bytes 40-4095:  Counter log — sequential 4-byte entries (big-endian)
 *
 * The counter uses a log-structured approach instead of erasing the whole
 * sector on every increment. Each authentication appends a 4-byte counter
 * value to the log. To read the current counter, we find the last non-empty
 * entry. After ~1014 authentications the log fills up, and we erase the
 * sector and rewrite everything.
 *
 * Why not just erase + rewrite each time? Flash sectors have a limited
 * erase lifetime (~100K cycles). With 1014 writes between erases, the
 * flash will last for ~100 million authentications instead of ~100K.
 *
 * RP2040 flash details:
 * - Flash is memory-mapped at XIP_BASE (0x10000000)
 * - Erase granularity: 4KB sectors (FLASH_SECTOR_SIZE)
 * - Write granularity: 256-byte pages (FLASH_PAGE_SIZE)
 * - Both erase and program require interrupts disabled, because ISRs
 *   that try to execute from flash while it's being written will crash.
 */

#include <string.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "storage.h"
#include "crypto.h"

// We use the last sector of flash. PICO_FLASH_SIZE_BYTES is set by the
// board config in the Pico SDK (2MB for standard Pico, 16MB for some
// Pro Micro boards — doesn't matter, last sector is always safe).
#define STORAGE_OFFSET  (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)

// Memory-mapped address for reading flash (no special API needed — just
// read it like regular memory, because the RP2040 maps flash into the
// address space via the XIP peripheral).
#define STORAGE_ADDR    ((const uint8_t *)(XIP_BASE + STORAGE_OFFSET))

// Layout offsets within the sector
#define MAGIC_OFFSET    0
#define SECRET_OFFSET   4
#define COUNTER_OFFSET  40    // First counter log entry
#define SECTOR_SIZE     FLASH_SECTOR_SIZE  // 4096

// How many 4-byte counter entries fit in the log area
#define MAX_COUNTER_ENTRIES ((SECTOR_SIZE - COUNTER_OFFSET) / 4)  // 1014

// Magic value — "FIDO FIDO" in hex, marks a valid storage sector
static const uint8_t MAGIC[] = { 0xF1, 0xD0, 0xF1, 0xD0 };

// RAM copy of master secret (read from flash at init)
static uint8_t master_secret[STORAGE_MASTER_SECRET_SIZE];

// Current counter value and position in the log
static uint32_t counter_value;
static size_t counter_entries;  // How many entries are in the log

// ---------------------------------------------------------------------------
// Flash helpers — must disable interrupts during flash operations
// ---------------------------------------------------------------------------

static void flash_erase_sector(void) {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(STORAGE_OFFSET, SECTOR_SIZE);
    restore_interrupts(ints);
}

// Write data at an offset within our sector. Length must be a multiple of
// FLASH_PAGE_SIZE (256 bytes), so we use a page-sized buffer and pad.
static void flash_write(size_t offset_in_sector, const uint8_t *data,
                        size_t len) {
    // flash_range_program requires 256-byte aligned writes. We build a
    // page buffer, copy our data in, and write the full page.
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0xFF, FLASH_PAGE_SIZE);  // 0xFF = erased state

    // For simplicity, we only write within a single page at a time.
    // Our writes are always small (4-40 bytes) and page-aligned.
    size_t page_start = (offset_in_sector / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
    size_t offset_in_page = offset_in_sector - page_start;

    // Read the current page content first (preserve existing data)
    memcpy(page, STORAGE_ADDR + page_start, FLASH_PAGE_SIZE);
    memcpy(page + offset_in_page, data, len);

    uint32_t ints = save_and_disable_interrupts();
    flash_range_program(STORAGE_OFFSET + page_start, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
}

// ---------------------------------------------------------------------------
// Counter log scanning
// ---------------------------------------------------------------------------

// Read a big-endian uint32 from a byte pointer.
static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void write_be32_buf(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)(val >> 24);
    p[1] = (uint8_t)(val >> 16);
    p[2] = (uint8_t)(val >> 8);
    p[3] = (uint8_t)val;
}

// Scan the counter log to find the last valid entry.
// Returns the counter value (0 if no entries).
static uint32_t scan_counter_log(size_t *num_entries) {
    const uint8_t *log = STORAGE_ADDR + COUNTER_OFFSET;
    uint32_t last_value = 0;
    size_t count = 0;

    for (size_t i = 0; i < MAX_COUNTER_ENTRIES; i++) {
        uint32_t entry = read_be32(log + i * 4);
        if (entry == 0xFFFFFFFF) {
            break;  // Reached erased area — end of log
        }
        last_value = entry;
        count++;
    }

    *num_entries = count;
    return last_value;
}

// ---------------------------------------------------------------------------
// Sector rebuild — erase and rewrite magic + secret + current counter
// ---------------------------------------------------------------------------

static void rebuild_sector(void) {
    // Build the header: magic(4) + secret(32) + padding(4) = 40 bytes
    uint8_t header[COUNTER_OFFSET];
    memset(header, 0xFF, sizeof(header));
    memcpy(header + MAGIC_OFFSET, MAGIC, 4);
    memcpy(header + SECRET_OFFSET, master_secret, STORAGE_MASTER_SECRET_SIZE);

    flash_erase_sector();
    flash_write(0, header, sizeof(header));

    // Write current counter as first log entry
    if (counter_value > 0) {
        uint8_t entry[4];
        write_be32_buf(entry, counter_value);
        flash_write(COUNTER_OFFSET, entry, 4);
        counter_entries = 1;
    } else {
        counter_entries = 0;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void storage_init(void) {
    // Check for magic bytes to detect first boot
    bool valid = (memcmp(STORAGE_ADDR + MAGIC_OFFSET, MAGIC, 4) == 0);

    if (valid) {
        // Existing storage — read master secret and scan counter log
        memcpy(master_secret, STORAGE_ADDR + SECRET_OFFSET,
               STORAGE_MASTER_SECRET_SIZE);
        counter_value = scan_counter_log(&counter_entries);
    } else {
        // First boot — generate master secret and initialize storage
        crypto_random(master_secret, STORAGE_MASTER_SECRET_SIZE);
        counter_value = 0;
        counter_entries = 0;
        rebuild_sector();
    }
}

const uint8_t *storage_get_master_secret(void) {
    return master_secret;
}

uint32_t storage_get_counter(void) {
    return counter_value;
}

void storage_increment_counter(void) {
    counter_value++;

    if (counter_entries >= MAX_COUNTER_ENTRIES) {
        // Log is full — erase and rebuild
        rebuild_sector();
    } else {
        // Append to log
        uint8_t entry[4];
        write_be32_buf(entry, counter_value);
        flash_write(COUNTER_OFFSET + counter_entries * 4, entry, 4);
        counter_entries++;
    }
}
