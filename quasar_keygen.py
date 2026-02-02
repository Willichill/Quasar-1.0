"""quasar_keygen.py — Quasar key generation utility

Generates cryptographically secure keys (16/24/32 bytes) and either prints
the hex value or writes the raw key to a file.

Usage (interactive):
  python3 quasar_keygen.py

Usage (one-shot):
  python3 quasar_keygen.py --size 32 --hex
  python3 quasar_keygen.py --size 16 --out mykey.bin

This file is a cleaned, importable version of the original `Quasar 1.1` keygen.
"""

import argparse
import secrets
import os
import sys


def generate_key(num_bytes: int) -> bytes:
    if num_bytes not in (16, 24, 32):
        raise ValueError("Unsupported key size: choose 16, 24, or 32 bytes")
    return secrets.token_bytes(num_bytes)


def write_key_file(path: str, key: bytes, binary: bool = True):
    mode = "wb" if binary else "w"
    with open(path, mode) as f:
        if binary:
            f.write(key)
        else:
            f.write(key.hex())


def run_cli(argv=None):
    p = argparse.ArgumentParser(description="Quasar key generator")
    p.add_argument("--size", type=int, choices=[16, 24, 32], default=32,
                   help="Key size in bytes (16=AES-128,24=AES-192,32=AES-256). Default: 32")
    p.add_argument("--hex", action="store_true", help="Print key as hex to stdout")
    p.add_argument("--out", type=str, help="Write key to FILE (raw binary). If --hex and --out are used, writes raw bytes")
    p.add_argument("--out-hex", type=str, help="Write key hex string to FILE (text)")
    p.add_argument("--quiet", action="store_true", help="Suppress informational messages")

    args = p.parse_args(argv)

    key = generate_key(args.size)

    if args.out:
        write_key_file(args.out, key, binary=True)
        if not args.quiet:
            print(f"Wrote {args.size}-byte key to {args.out} (raw binary)")

    if args.out_hex:
        write_key_file(args.out_hex, key, binary=False)
        if not args.quiet:
            print(f"Wrote hex key to {args.out_hex}")

    if args.hex or (not args.out and not args.out_hex):
        # Print hex to stdout by default if no file outputs were requested
        print(key.hex())


def interactive():
    print("Quasar key generator")
    while True:
        try:
            s = input("Choose key size in bytes (16/24/32) or 'q' to quit [32]: ").strip()
            if s == "":
                size = 32
            elif s.lower() in ("q", "quit", "exit"):
                return
            else:
                size = int(s)
            if size not in (16, 24, 32):
                print("Invalid size — must be 16, 24, or 32")
                continue

            out = input("Write raw key to file? (enter path or leave empty to skip): ").strip()
            out_hex = input("Write hex to file? (enter path or leave empty to skip): ").strip()
            show_hex = input("Print hex to screen? (Y/n): ").strip().lower() or "y"

            key = generate_key(size)

            if out:
                write_key_file(out, key, binary=True)
                print(f"Wrote raw key to {out}")
            if out_hex:
                write_key_file(out_hex, key, binary=False)
                print(f"Wrote hex key to {out_hex}")
            if show_hex.startswith("y"):
                print("Key (hex):", key.hex())

            cont = input("Generate another? (Y/n): ").strip().lower() or "y"
            if cont != "y":
                break

        except KeyboardInterrupt:
            print("\nAborted.")
            return
        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    # If script is called with args, use CLI mode; otherwise interactive
    if len(sys.argv) > 1:
        run_cli()
    else:
        interactive()
