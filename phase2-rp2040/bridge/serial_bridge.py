#!/usr/bin/env python3
"""
Serial bridge — forwards CTAPHID packets between UDP and USB serial.

This sits between the Phase 1 test clients (which speak UDP on port 7112)
and the RP2040 firmware (which reads/writes 64-byte packets over USB serial).

    [test_fido2_client.py] --UDP--> [serial_bridge.py] --serial--> [RP2040]
                           <--UDP--                    <--serial--

Usage:
    python3 serial_bridge.py /dev/cu.usbmodem*

Requires: pyserial (pip install pyserial)
"""

import serial
import socket
import sys
import time

PACKET_SIZE = 64
UDP_HOST = "127.0.0.1"
UDP_PORT = 7112


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <serial-port>")
        print(f"  e.g.: {sys.argv[0]} /dev/cu.usbmodem11101")
        sys.exit(1)

    port = sys.argv[1]

    # Open serial connection to the Pico
    ser = serial.Serial(port, baudrate=115200, timeout=0.01)
    time.sleep(1.0)          # Let Pico finish USB init
    ser.reset_input_buffer()  # Flush any startup data

    # Listen for UDP packets from test clients on port 7112
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, UDP_PORT))
    sock.setblocking(False)

    print(f"Bridge: UDP {UDP_HOST}:{UDP_PORT} <-> Serial {port}")
    print("Waiting for packets...")

    client_addr = None

    while True:
        # --- UDP → Serial: forward packets from test client to Pico ---
        try:
            data, addr = sock.recvfrom(PACKET_SIZE)
            if len(data) == PACKET_SIZE:
                client_addr = addr
                ser.write(data)
                ser.flush()
        except BlockingIOError:
            pass

        # --- Serial → UDP: forward responses from Pico to test client ---
        if ser.in_waiting >= PACKET_SIZE:
            data = ser.read(PACKET_SIZE)
            if len(data) == PACKET_SIZE and client_addr is not None:
                sock.sendto(data, client_addr)

        time.sleep(0.001)  # Prevent busy loop


if __name__ == "__main__":
    main()
