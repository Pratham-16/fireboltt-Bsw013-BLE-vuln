"""
CRC-16/ARC checksum used by the BSW013's custom BLE command protocol.

Polynomial 0x8005 (reflected: 0xA001), reflected input/output, init 0x0000,
no final XOR. Computed over all packet bytes from the Command field
(offset 6) to the end of the packet.

Verified against 25 independent real (data, checksum) pairs pulled from a
captured HCI snoop log -- 25/25 exact matches.
"""


def crc16_arc(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


if __name__ == "__main__":
    # Example: command field onward for a sample packet
    example = bytes.fromhex("0401007F1A061D01")
    print(f"CRC-16/ARC: {crc16_arc(example):04X}")
