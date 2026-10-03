#!/usr/bin/env python3

import argparse
from pathlib import Path


HEADER_SIZE = 64  # 512 бит


def xor_with_key(data: bytes, key: bytes, offset_bits: int) -> bytes:
    """
    Выполняет побитовый XOR данных с циклически повторяющимся ключом.
    """
    if not key:
        raise ValueError("Файл ключа не должен быть пустым")

    result = bytearray(len(data))
    key_bits = len(key) * 8

    for bit_index in range(len(data) * 8):
        data_byte_index = bit_index // 8
        data_bit_index = 7 - (bit_index % 8)

        key_bit_position = (offset_bits + bit_index) % key_bits
        key_byte_index = key_bit_position // 8
        key_bit_index = 7 - (key_bit_position % 8)

        data_bit = (data[data_byte_index] >> data_bit_index) & 1
        key_bit = (key[key_byte_index] >> key_bit_index) & 1

        decrypted_bit = data_bit ^ key_bit

        if decrypted_bit:
            result[data_byte_index] |= 1 << data_bit_index

    return bytes(result)


def main():
    parser = argparse.ArgumentParser(
        description="Расшифрование файла XOR"
    )

    parser.add_argument(
        "encrypted_file",
        help="Путь к зашифрованному файлу"
    )
    parser.add_argument(
        "key_file",
        help="Путь к файлу ключа"
    )
    parser.add_argument(
        "output_file",
        help="Путь к расшифрованному файлу"
    )

    args = parser.parse_args()

    encrypted_path = Path(args.encrypted_file)
    key_path = Path(args.key_file)
    output_path = Path(args.output_file)

    encrypted_file = encrypted_path.read_bytes()

    if len(encrypted_file) < HEADER_SIZE:
        raise ValueError(
            "Зашифрованный файл слишком короткий: "
            "отсутствует 512-битный заголовок"
        )

    # Первые 64 байта содержат смещение.
    header = encrypted_file[:HEADER_SIZE]
    encrypted_data = encrypted_file[HEADER_SIZE:]

    offset_bits = int.from_bytes(header, byteorder="big")
    key = key_path.read_bytes()

    decrypted_data = xor_with_key(
        data=encrypted_data,
        key=key,
        offset_bits=offset_bits
    )

    output_path.write_bytes(decrypted_data)

    print(f"Файл расшифрован: {output_path}")
    print(f"Прочитанное смещение: {offset_bits} бит")


if __name__ == "__main__":
    main()
