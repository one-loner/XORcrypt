#!/usr/bin/env python3

import argparse
from pathlib import Path


HEADER_SIZE = 64  # 512 бит


def xor_with_key(data: bytes, key: bytes, offset_bits: int) -> bytes:
    """Побитовый XOR данных с циклически повторяющимся ключом."""
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

        encrypted_bit = data_bit ^ key_bit

        if encrypted_bit:
            result[data_byte_index] |= 1 << data_bit_index

    return bytes(result)


def main():
    parser = argparse.ArgumentParser(
        description="Шифрование файла с использованием XOR"
    )

    parser.add_argument(
        "input_file",
        help="Путь к исходному файлу"
    )

    parser.add_argument(
        "key_file",
        help="Путь к файлу ключа"
    )

    parser.add_argument(
        "offset",
        type=int,
        help="Смещение ключа в битах"
    )

    args = parser.parse_args()

    if args.offset < 0:
        raise ValueError("Смещение не может быть отрицательным")

    input_path = Path(args.input_file)
    key_path = Path(args.key_file)

    if not input_path.is_file():
        raise FileNotFoundError(
            f"Исходный файл не найден: {input_path}"
        )

    if not key_path.is_file():
        raise FileNotFoundError(
            f"Файл ключа не найден: {key_path}"
        )

    data = input_path.read_bytes()
    key = key_path.read_bytes()

    encrypted_data = xor_with_key(
        data,
        key,
        args.offset
    )

    try:
        # Сохраняем смещение в первых 64 байтах.
        header = args.offset.to_bytes(
            HEADER_SIZE,
            byteorder="big",
            signed=False
        )
    except OverflowError:
        raise ValueError(
            "Смещение не помещается в 512 бит"
        )

    output_path = input_path.with_name(
        input_path.name + ".crypt"
    )

    output_path.write_bytes(header + encrypted_data)

    print(f"Файл зашифрован: {output_path}")
    print(f"Смещение: {args.offset} бит")


if __name__ == "__main__":
    main()
