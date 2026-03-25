/**
 * TinyUSB configuration for FIDO U2F HID device.
 *
 * TinyUSB is the USB stack bundled with the Pico SDK. It supports many
 * USB device classes (serial, mass storage, MIDI, HID, etc.) and both
 * host and device modes. This header tells it exactly what we need:
 * device mode, HID class only, 64-byte packets.
 *
 * TinyUSB finds this file by name — it must be called "tusb_config.h"
 * and be on the include path. The Pico SDK's CMake integration handles
 * the include path for us.
 */

#ifndef TUSB_CONFIG_H
#define TUSB_CONFIG_H

// ---------------------------------------------------------------------------
// USB mode: device (not host)
// ---------------------------------------------------------------------------
// The RP2040 has one USB port (RHPORT0). We configure it as a device.
// OPT_MODE_DEVICE means "I'm a peripheral, the computer is the host."
#define CFG_TUSB_RHPORT0_MODE   OPT_MODE_DEVICE

// ---------------------------------------------------------------------------
// Device class configuration
// ---------------------------------------------------------------------------
// Enable exactly one class: HID. Disable everything else to save code space.
// When we used pico_enable_stdio_usb, the SDK enabled CFG_TUD_CDC=1 behind
// the scenes — that's how printf/getchar worked over USB serial. Now we're
// taking over USB ourselves.

#define CFG_TUD_HID     1       // Human Interface Device — what FIDO keys use
#define CFG_TUD_CDC     0       // No serial (was 1 when we used stdio_usb)
#define CFG_TUD_MSC     0       // No mass storage
#define CFG_TUD_MIDI    0       // No MIDI
#define CFG_TUD_VENDOR  0       // No vendor-specific class

// ---------------------------------------------------------------------------
// HID endpoint buffer size
// ---------------------------------------------------------------------------
// This is the max report size TinyUSB will accept/send on the HID endpoints.
// FIDO U2F HID uses exactly 64-byte reports (matching CTAPHID_PACKET_SIZE).
// This value must be >= our report size.
#define CFG_TUD_HID_EP_BUFSIZE  64

#endif // TUSB_CONFIG_H
