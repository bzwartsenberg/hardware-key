/**
 * USB descriptors and TinyUSB callbacks for FIDO U2F HID device.
 *
 * This file defines the device's USB identity — everything the host needs
 * to know to communicate with us. Think of it as a structured self-description
 * that the host reads during enumeration (the "who are you?" handshake when
 * you plug in a USB device).
 *
 * Descriptors are nested like this:
 *
 *   Device Descriptor        "I'm a USB 2.0 device, VID=1209, PID=F1D0"
 *     └── Config Descriptor  "I have 1 interface, draw 100mA"
 *           └── Interface     "I'm a HID device"
 *                 ├── HID     "My report descriptor is N bytes"
 *                 ├── EP IN   "Interrupt IN, 64 bytes, poll every 5ms"
 *                 └── EP OUT  "Interrupt OUT, 64 bytes, poll every 5ms"
 *
 * Plus two special descriptors:
 *   - HID Report Descriptor: tells the host the format of our data packets
 *   - String Descriptors: human-readable names (manufacturer, product)
 *
 * TinyUSB doesn't use global variables for descriptors. Instead, it calls
 * callback functions (tud_descriptor_*_cb) when the host requests each
 * descriptor. We provide these callbacks below.
 */

#include "tusb.h"

// ---------------------------------------------------------------------------
// HID Report Descriptor — the data format description
// ---------------------------------------------------------------------------
//
// Every HID device must describe what its data packets look like. A keyboard
// says "byte 0 is modifier keys, bytes 1-6 are keycodes." A mouse says
// "3 bytes: buttons, X delta, Y delta."
//
// For FIDO, it's simpler: "I send and receive 64-byte opaque blobs."
// The key part is the Usage Page (0xF1D0) — this is the FIDO Alliance's
// registered USB usage page. When the OS sees this, it knows to expose
// the device to WebAuthn/FIDO APIs instead of treating it as a keyboard
// or mouse.
//
// This descriptor is defined by the FIDO U2F HID specification, section 2.
// Every conforming U2F HID device uses the same report descriptor.

static const uint8_t desc_hid_report[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance — 0xF1D0)
    0x09, 0x01,         // Usage (U2F HID Authenticator Device)
    0xA1, 0x01,         // Collection (Application)

    // Input report: device → host (64 bytes)
    0x09, 0x20,         //   Usage (Input Report Data)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits per field)
    0x95, 0x40,         //   Report Count (64 fields = 64 bytes)
    0x81, 0x02,         //   Input (Data, Variable, Absolute)

    // Output report: host → device (64 bytes)
    0x09, 0x21,         //   Usage (Output Report Data)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits per field)
    0x95, 0x40,         //   Report Count (64 fields = 64 bytes)
    0x91, 0x02,         //   Output (Data, Variable, Absolute)

    0xC0,               // End Collection
};

// ---------------------------------------------------------------------------
// Device Descriptor — the top-level identity
// ---------------------------------------------------------------------------
//
// This is the first thing the host reads after reset. It identifies:
//   - USB version (2.0)
//   - Vendor/Product ID (how the OS identifies us)
//   - Number of configurations (always 1 for simple devices)
//
// bDeviceClass = 0 means "look at the interface descriptors to determine
// my class." This is standard for HID devices — the class is defined at
// the interface level, not the device level. (Composite devices like a
// keyboard+FIDO key have multiple interfaces with different classes.)

static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0210,   // USB 2.1 (2.1 adds BOS descriptor support)
    .bDeviceClass       = 0x00,     // Class defined at interface level
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,  // Control EP max packet (64)

    // VID/PID: 0x1209 is the pid.codes open-source vendor ID.
    // 0xF1D0 is a placeholder PID — for personal use, anything works.
    // For a "real" product, you'd request a PID from pid.codes.
    .idVendor           = 0x1209,
    .idProduct          = 0xF1D0,
    .bcdDevice          = 0x0100,   // Device version 1.0.0

    // String descriptor indices — 0 means "no string"
    // These are the human-readable names your OS shows in System Information
    .iManufacturer      = 0x01,     // Index 1 → "DIY"
    .iProduct           = 0x02,     // Index 2 → "FIDO U2F Key"
    .iSerialNumber      = 0x03,     // Index 3 → "000001"

    .bNumConfigurations = 0x01,     // One configuration (almost always 1)
};

// TinyUSB callback: host requests the device descriptor
const uint8_t *tud_descriptor_device_cb(void) {
    return (const uint8_t *)&desc_device;
}

// ---------------------------------------------------------------------------
// Configuration Descriptor — what the device can do
// ---------------------------------------------------------------------------
//
// After reading the device descriptor, the host asks for the configuration
// descriptor. This is actually a *bundle* of descriptors concatenated
// together: the config descriptor itself, plus all interface descriptors,
// HID descriptors, and endpoint descriptors within that configuration.
//
// We use TinyUSB's TUD_HID_INOUT_DESCRIPTOR macro to generate the
// interface + HID + endpoint descriptors. "INOUT" means we get both an
// IN endpoint (device → host) and an OUT endpoint (host → device).
// Both are interrupt-type endpoints — the host polls them on a fixed
// schedule.
//
// Why interrupt endpoints? FIDO spec requires them. They provide
// guaranteed polling interval (the host checks for data every N ms),
// which is important for responsive authentication. The alternative
// (bulk endpoints) has no timing guarantee — the host can deprioritize
// them under load.

#define ENDPOINT_IN   0x81  // EP1, direction IN  (device → host)
#define ENDPOINT_OUT  0x01  // EP1, direction OUT (host → device)
//
// Endpoint addresses encode both the endpoint number and direction in
// one byte: bit 7 = direction (1=IN, 0=OUT), bits 3:0 = endpoint number.
// So 0x81 = EP1 IN, 0x01 = EP1 OUT. EP0 is reserved for control.

#define CONFIG_TOTAL_LEN  (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)

static const uint8_t desc_configuration[] = {
    // Configuration descriptor header
    TUD_CONFIG_DESCRIPTOR(
        1,                  // Config number (1-based)
        1,                  // Number of interfaces
        0,                  // String index (0 = no name)
        CONFIG_TOTAL_LEN,   // Total length of this bundle
        0x00,               // Attributes: bus-powered (no self-power, no remote wakeup)
        100                 // Max power in mA (100mA is plenty for a crypto key)
    ),

    // HID interface with IN and OUT endpoints
    // This macro expands to: interface descriptor + HID descriptor +
    // endpoint descriptor (OUT) + endpoint descriptor (IN)
    TUD_HID_INOUT_DESCRIPTOR(
        0,                          // Interface number (0-based)
        0,                          // String index (0 = no name)
        HID_ITF_PROTOCOL_NONE,      // Protocol: none (not a boot keyboard/mouse)
        sizeof(desc_hid_report),    // HID report descriptor length
        ENDPOINT_OUT,               // OUT endpoint address
        ENDPOINT_IN,                // IN endpoint address
        CFG_TUD_HID_EP_BUFSIZE,     // Endpoint max packet size (64 bytes)
        5                           // Polling interval in ms (FIDO spec: ≤5ms)
    ),
};

// TinyUSB callback: host requests the configuration descriptor
const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;  // We only have one configuration
    return desc_configuration;
}

// ---------------------------------------------------------------------------
// HID Report Descriptor callback
// ---------------------------------------------------------------------------
// The host requests this after seeing we're an HID device. It's the
// "what does your data look like?" descriptor defined at the top.

const uint8_t *tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;  // We only have one HID interface
    return desc_hid_report;
}

// ---------------------------------------------------------------------------
// String Descriptors — human-readable names
// ---------------------------------------------------------------------------
//
// These are optional but nice — they show up in your OS's USB device list.
// String index 0 is special: it's the language ID (English).
// Other indices match the iManufacturer/iProduct/iSerialNumber fields
// from the device descriptor.
//
// TinyUSB wants these as arrays of 16-bit Unicode characters (UTF-16).
// For ASCII strings, each character is just the ASCII value zero-extended
// to 16 bits.

// Language ID: US English
static const uint16_t string_lang[] = { 0x0409 };

// Convert a string literal to a uint16_t array at compile time
// (TinyUSB needs UTF-16, not UTF-8)
static const uint16_t string_manufacturer[] = { 'D','I','Y' };
static const uint16_t string_product[]      = { 'F','I','D','O',' ','U','2','F',' ','K','e','y' };
static const uint16_t string_serial[]       = { '0','0','0','0','0','1' };

static const struct {
    const uint16_t *str;
    uint8_t len;  // number of uint16_t characters
} string_table[] = {
    { string_lang,         1 },   // Index 0: language
    { string_manufacturer, 3 },   // Index 1: "DIY"
    { string_product,      12 },  // Index 2: "FIDO U2F Key"
    { string_serial,       6 },   // Index 3: "000001"
};

// Buffer for building the string descriptor response.
// Format: [total_length, type=3, UTF-16 characters...]
static uint16_t _desc_str_buf[32 + 1];

// TinyUSB callback: host requests a string descriptor
const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;

    if (index >= sizeof(string_table) / sizeof(string_table[0])) {
        return NULL;
    }

    uint8_t char_count = string_table[index].len;
    const uint16_t *chars = string_table[index].str;

    // First uint16_t encodes: low byte = total descriptor length,
    // high byte = descriptor type (3 = string)
    _desc_str_buf[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 + 2 * char_count));

    for (uint8_t i = 0; i < char_count; i++) {
        _desc_str_buf[1 + i] = chars[i];
    }

    return _desc_str_buf;
}

// ---------------------------------------------------------------------------
// HID callbacks — required by TinyUSB even if we don't use them
// ---------------------------------------------------------------------------

// Called when the host sends a GET_REPORT control request.
// FIDO doesn't use this (data goes through interrupt endpoints), but
// TinyUSB requires the callback to exist.
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                                hid_report_type_t report_type,
                                uint8_t *buffer, uint16_t reqlen) {
    (void)instance; (void)report_id; (void)report_type;
    (void)buffer; (void)reqlen;
    return 0;
}

// Called when the host sends data — either via SET_REPORT control request
// or via the interrupt OUT endpoint. For FIDO, all data comes through the
// OUT endpoint. This is where we receive 64-byte CTAPHID packets.
//
// We DON'T process the packet here — we just copy it to a buffer and set
// a flag. Processing happens in the main loop. This keeps the USB callback
// fast and avoids any re-entrancy issues.

// These are extern — main.c owns the actual storage
extern volatile bool hid_packet_received;
extern uint8_t hid_packet_buf[64];

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                            hid_report_type_t report_type,
                            const uint8_t *buffer, uint16_t bufsize) {
    (void)instance; (void)report_id; (void)report_type;

    if (bufsize == 64) {
        memcpy(hid_packet_buf, buffer, 64);
        hid_packet_received = true;
    }
}
