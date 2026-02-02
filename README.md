Quasar tools ##CLOSE ALL FILES OR PRESS CONTROLL S TO SAVE THE EDITED FILES!!!##
===========

This workspace contains small educational utilities related to AES/CBC and a
simple interactive front-end.

Files of interest
- `aes_cbc.py`         — educational AES-128 + CBC implementation and CLI (keep for testing/learning)
- `quasar_frontend.py` — interactive front-end (preferred name; replaces the old `Quasar 1.0`)
- `quasar_keygen.py`   — key generation utility (preferred name; replaces the old `Quasar 1.1`)
- `tests/`             — pytest tests for the AES/CBC implementation

Quick usage
- Generate a 32-byte key (interactive):

```bash
python3 quasar_keygen.py
```

- Generate a 16-byte key and print hex:

```bash
python3 quasar_keygen.py --size 16 --hex
```

- Start the interactive front-end:

```bash
python3 quasar_frontend.py
```

Notes
- The AES implementation is educational and not constant-time. For production use,
  prefer a vetted library such as `cryptography` or `PyCryptodome`.
- The legacy files `Quasar 1.0` and `Quasar 1.1` were removed and replaced with
  the clearer module names `quasar_frontend.py` and `quasar_keygen.py`.
  If you need the old filenames preserved for some reason, let me know and I can
  add small compatibility wrappers.

Sharing this project — what to include
-------------------------------------

- Source code: `aes_cbc.py`, `quasar_frontend.py`, `quasar_keygen.py`
- Tests: the `tests/` directory (includes pytest tests that verify AES/CBC)
- Dependency manifest: `requirements.txt` (used by CI to install `pytest`)
- CI configuration: `.github/workflows/ci.yml` (optional, but useful)
- README: this file with usage notes and the sharing checklist
- Optional: a small `LICENSE` file if you want to specify reuse terms

Packaging checklist (minimal)

1. Copy the files listed above into a single folder.
2. Run the tests locally to verify everything works:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -q
```

3. Optionally enable the GitHub Actions workflow by pushing the repository to
   a GitHub repo (the `.github/workflows/ci.yml` file is included).

Quick file summaries (one-liners)
--------------------------------
- `aes_cbc.py` — Educational AES-128 implementation (encrypt/decrypt block
  primitives), PKCS#7 padding, CBC mode helpers, and a small file-level CLI
  (encrypt/decrypt files; prepend IV). Good for learning and tests; not
  constant-time.
- `quasar_keygen.py` — Secure key generator (CLI + interactive). Generates
  16/24/32-byte keys and can print hex, write raw bytes, or write hex string
  to a file.
- `quasar_frontend.py` — Interactive menu-driven front-end. Delegates
  encryption/decryption to `aes_cbc.py` and can invoke the key generator
  (if `quasar_keygen.py` is present).
- `tests/` — Pytest tests verifying AES-128 ECB vector and CBC roundtrips,
  padding edge cases, and file-roundtrip behavior.
- `requirements.txt` — Minimal requirements for running tests (`pytest`).
- `.github/workflows/ci.yml` — Optional CI workflow that runs `pytest` on
  pushes and PRs.

Important notes for sharing
---------------------------
- Security: This AES implementation is educational and not suitable for
  production 
- AES key sizes: `quasar_keygen.py` supports 16/24/32 byte keys, but the
  included AES implementation (`aes_cbc.py`) currently supports AES-128
  (16-byte keys) only. If you plan to use 24/32-byte keys, extend `aes_cbc.py`
  or use a standard crypto library.

Recommended key handling (short)
--------------------------------
- Generate a fresh random key for each distinct purpose. For AES-CBC,
  generate a new random 16-byte IV per encryption operation and never reuse
  the same IV+key pair for different plaintexts.
- Store keys securely: use OS-provided key stores (e.g., macOS Keychain,
  Linux keyrings) or an encrypted secrets store. If you must keep a raw key
  file, restrict permissions (chmod 600) and never commit it to version control.
- Prefer storing/transmitting the key as raw bytes only to trusted systems;
  use hex or base64 for safe text transport if needed, but keep the canonical
  copy in binary form on secure storage.
- Rotate keys periodically and have a plan to revoke/replace compromised keys.
- For production workloads, use a vetted crypto library and higher-level
  practices (authenticated encryption like AES-GCM or an HSM/KMS for key
  management).


Example (non-interactive) — use `key.bin` in the current directory
---------------------------------------------------------------
This example shows the minimal non-interactive workflow using `key.bin` in
the current directory. It assumes you have a `plaintext.txt` file to encrypt.

1) Generate a 16-byte AES key and save as raw bytes in `key.bin`:

```bash
python3 quasar_keygen.py --size 16 --out key.bin
```

2) Restrict the key file permissions so only your user can read it:

```bash
chmod 600 key.bin
```

3) Encrypt `plaintext.txt` to `encrypted.bin` using the module helpers
   (this reads `key.bin` as raw bytes):

```bash
python3 - <<'PY'
from aes_cbc import parse_key, file_encrypt
key = parse_key('key.bin')
file_encrypt(key, 'plaintext.txt', 'encrypted.bin')
print('Wrote encrypted.bin')
PY
```

4) Decrypt `encrypted.bin` back to `decrypted.txt` and verify:

```bash
python3 - <<'PY'
from aes_cbc import parse_key, file_decrypt
key = parse_key('key.bin')
file_decrypt(key, 'encrypted.bin', 'decrypted.txt')
print('Wrote decrypted.txt')
PY

5) Verify the roundtrip:

```bash
diff plaintext.txt decrypted.txt || echo 'Mismatch!'
```

Notes:
- `parse_key('key.bin')` will detect a file and read raw bytes; if you have
  the key as a hex string instead, `parse_key` accepts that too.
- The encrypted file format is `IV || ciphertext` (IV = first 16 bytes).
- Always keep `key.bin` secret and avoid committing it to VCS.

⠀⠀⠀⠀⠀⢀⣤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⢤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡼⠋⠀⣀⠄⡂⠍⣀⣒⣒⠂⠀⠬⠤⠤⠬⠍⠉⠝⠲⣄⡀⠀⠀
⠀⠀⠀⢀⡾⠁⠀⠊⢔⠕⠈⣀⣀⡀⠈⠆⠀⠀⠀⡍⠁⠀⠁⢂⠀⠈⣷⠀⠀
⠀⠀⣠⣾⠥⠀⠀⣠⢠⣞⣿⣿⣿⣉⠳⣄⠀⠀⣀⣤⣶⣶⣶⡄⠀⠀⣘⢦⡀
⢀⡞⡍⣠⠞⢋⡛⠶⠤⣤⠴⠚⠀⠈⠙⠁⠀⠀⢹⡏⠁⠀⣀⣠⠤⢤⡕⠱⣷
⠘⡇⠇⣯⠤⢾⡙⠲⢤⣀⡀⠤⠀⢲⡖⣂⣀⠀⠀⢙⣶⣄⠈⠉⣸⡄⠠⣠⡿
⠀⠹⣜⡪⠀⠈⢷⣦⣬⣏⠉⠛⠲⣮⣧⣁⣀⣀⠶⠞⢁⣀⣨⢶⢿⣧⠉⡼⠁
⠀⠀⠈⢷⡀⠀⠀⠳⣌⡟⠻⠷⣶⣧⣀⣀⣹⣉⣉⣿⣉⣉⣇⣼⣾⣿⠀⡇⠀
⠀⠀⠀⠈⢳⡄⠀⠀⠘⠳⣄⡀⡼⠈⠉⠛⡿⠿⠿⡿⠿⣿⢿⣿⣿⡇⠀⡇⠀
⠀⠀⠀⠀⠀⠙⢦⣕⠠⣒⠌⡙⠓⠶⠤⣤⣧⣀⣸⣇⣴⣧⠾⠾⠋⠀⠀⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠶⣭⣒⠩⠖⢠⣤⠄⠀⠀⠀⠀⠀⠠⠔⠁⡰⠀⣧⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠲⢤⣀⣀⠉⠉⠀⠀⠀⠀⠀⠁⠀⣠⠏⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠒⠲⠶⠤⠴⠒⠚⠁
