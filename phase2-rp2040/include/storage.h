#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define STORAGE_MASTER_SECRET_SIZE 32

// Initialize storage: reads from flash. On first boot (no magic found),
// generates a random master secret and writes it. Call after crypto_init().
void storage_init(void);

// Get a pointer to the master secret (32 bytes).
// Valid for the lifetime of the program — it's in a static buffer.
const uint8_t *storage_get_master_secret(void);

// Get the current sign counter value.
uint32_t storage_get_counter(void);

// Increment the counter and persist it to flash.
void storage_increment_counter(void);

#endif // STORAGE_H
