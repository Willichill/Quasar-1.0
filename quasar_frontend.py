"""quasar_frontend.py — interactive front-end that delegates crypto tasks to aes_cbc.py.

This is a cleaned copy of the original `Quasar 1.0` front-end. It delegates
AES/CBC work to `aes_cbc.py` and key generation to `quasar_keygen.py` (if
available).
"""

import os
import shutil
import random
import time
import textwrap
import hashlib

# Try to import crypto helpers and the keygen module (optional)
try:
    from aes_cbc import file_encrypt, file_decrypt, parse_key, run_selftest
except Exception:
    file_encrypt = None
    file_decrypt = None
    parse_key = None
    run_selftest = None

try:
    import quasar_keygen
    keygen_available = True
except Exception:
    quasar_keygen = None
    keygen_available = False


boot = input("Hello, press any key to continue: ")
# Oooooooooooooooooooohhhh Cool quasar textart I found online
ascii_block = textwrap.dedent(r"""
.......................................................................................:^?PBPY?!^
......::::..............:....^:......................................................::^?PBGJ!~^:
...:::::::.:........................................................................:^!YGBP7~^:..
...:::::.:.::..........................:::........................................:^7YGP5?!^:....
..:::::::::::.........................::::.......................................:!5GPJ!~^:......
:::::::::::::...........................:^:.....:..............................:^75G57~^::.......
::^^^^:::::::::.::::::::....:....::......::..................................::~YGGY!^::.........
:^^^^^^^:::::::::::::::::::.:....::......:::...............................::~JPGY7~::...........
:^^^^^::::::::::..::::::::::::::::::::::::::..............................:^?PGY7~::.............
:^^^:::::::::::::::::::::^:::::::::::::::::::...........................::!5GY7^::...............
:^^^^::::::::::::::::::^^^^^:::::::::::::::::..........................:^YG57~^::................
^^^^::::::::::::::::::::^^^^^^:^^^^^::::::::::::::....................:7P57~^::..................
^^^^^:::::^:::::::::::^^^^^^^^^^^^^^^^^::::::::::::::...............:~JY7~^:::...................
::^^^^::::^^:::::::^^^^^^^^~^^^^~~~~~~^^^^^:::::::::::...........:.^J5?~:::......:...............
^^^^^^^^^:^^^^^^^^^^^^:^^^^^^^~~~~~~~~~~~~~~^^^^::^::::..:::::::::75J~::.........................
^^^^^^^::::::^^^^^^^:::^^^^^~~~~~~~~~~~~~~~~~~~^^^^^^^:::::::^^^!Y?~::...........................
::^^^^:::::::^^^^^^^^^^^^^^^~~~^^~~~!!!!!!!!!!!~~~~~~~^^^^^^^^!JJ!^:::...........................
::::::::::::::^^^^^^^^^^^^^^^~~~~~~~!!!!!!!777777!!!!~~~~~~^~7J7~^^:::...........................
::::::::::::::^^^^^^^^^^^^^^^~~~~~~!!!!!777????????777!!!~~7J7~^^^^^::::...................:.....
:::::.:.::::::::^^^^^^^^^^^^^^~~~~~~!!!7???JJJYYYYYJJ??7!7J?!!~~~^^^^:::................:..::.::.
...........::::::::^^^^^^^^^^~~~~~~~~!!7?JJYY5PGGGGGP5YJJJ?77!!~~~~^^::............:....::::::::.
............:::::::::^:::^^^~~~~~~~~!!!7?JY55PBBB##BBGGP5Y??77!!!~~^^:::................::::...::
.:..........::::::::::::^^^^^~~~~~~~!!!7?JY5PGB###&&&&#BGPYJ?777!!~^^:::::...........::.:::::::::
............::::::::::::::^^^^^~~~~~~!!!7?JY5GGB###&&&&#BGPYJ?77!!~~^^:::::..........::::::::::::
..............::.::::::::::^^^^^^~~~~~!!77?JY5PGBB######BGP5JJ?7!!~~^^^^::::::::......::::::^::::
....:..........::.:::::::::^^^^^^~~!!!!!77??JYY5PPGGGGGGPP5YJJ?77!!!~~^^^^^::::::::::::^:^^^^^^^^
....:..........::::::::::::^^^^^^^^~!7777???JJYYYYY55555YYYJJJ?777!!!~~~^^^^^^:::::::^:::^^^^^^^^
::............:::::::::::::^^^^~~~^~~!!77?JJJJJJJJJJJYYJJJ?????777!!!!~~~^^^^^^^::::^^^^^::::::^^
.::...........:::::::::::::^^^^^~~!!!!!!77?J?????JJJ?????????7777!!!!~!~~~^^^^^^^^::::^^:::::::::
:.::..:::.....::::::::^^^^^^^^^^^~~~~!!!??777777777777777?777!7!!!~!~~~~~~^^^^^^^^:::::::::::::::
:::::::::::::::::::::::^^^^^^^^^^^~~~!7J?!7!!!!!!!!!!!!!!!!!!!!!!!~~~~~^^^^^^^^^^^^::::::::::::::
::::::::.::::::::::::::::^^^^^^^^~~~7??!~~!!!!!!!!~~!~!!!~~~~~~~~~~~~~^^^^^^^^^^^^^::::::::::::::
:::::::...::::::::::::::::^^^^^^~~~?J!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^::::::::::::::
.::::::.:::::::::::::::::^^^^^~~~7Y?~^~~~~~~~~~^^^~~~~~~~^^^^^^^~^^^^^^^^^^^^^^^^^^::::::::::::::
..::::::::::::::::::::::::^^^^^!JY7^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^:::::::::::::::
.....:::::::::::::::::::::^^^~?Y?~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^::::::^^^:^^:::::::::.:..:::
......::::::::::::::::::::^~7YJ!^^^^^^^^^^^^^^^^^^^^^^^^^^^^^::::::::::::::::::::::::::..........
........:::::::::::::::::^7YY7^::::::::^:::::::::^^^^::::::::::::::::::::::::::::::::::..........
........:::::::::::::::^!Y57^:::::::::::::::::::::::::::::::::::::::::::::::::::::::::...........
.................::::^7Y5?^::::::::::::::::::::::::::::::::::..:::::::::::::::::::::::...........
..................::~J5J~:::::::::::::::::::::::::::::::.........:::.:::::::::::::::.............
..................::~JJ!:::::::::::::::::::::::.......................::::::::.....::............
...............::^7?7^:::.......::::::...............................::::::::....................
.............::^!?7~:..............................................:.:::::.......................
...........:::~77~:..................................................::::........................
""")


def print_block(block, delay=0):
    for line in block.splitlines():
        if line.strip() == "":
            print()
        else:
            print(line)
        if delay:
            time.sleep(delay)

if boot == "skip_boot":
    print()
    print()
else:
    # boot animation
    for _ in range(3):
        print("\rBooting up.", end="", flush=True); time.sleep(0.4)
        print("\rBooting up..", end="", flush=True); time.sleep(0.4)
        print("\rBooting up...", end="", flush=True); time.sleep(0.4)
    print()
    print_block(ascii_block, delay=0.1)
    print()


running = True

while running: 

    choice = input("Quasar 1.0 ~ % ").strip()

    if choice == "help":
        help_block = textwrap.dedent("""\
        +-------------------------------------------------------------------------+
        | Definition: Quasar is an encryption and decryption front-end.           |
        | This program delegates cryptographic operations to a separate module.   |
        | Coded by: Walliam Chang and Alex Tangathan.                             |
        |                                                                         |
        | Commands:                                                               |
        |    help    - show this message                                          |
        |    ace     - encryption/decryption submenu for the aes_cbc.py file      |
        |    keygen  - run the key generator (quasar_keygen.py)                   |
        |    quit    - exit the program                                           |
        |    insp    - short inspirational message                                |
        |    hash    - SHA-512 hash of a string                                   |
        |    vert    - verify SHA-512 hash                                        |
        +-------------------------------------------------------------------------+
        """)
        print_block(help_block, delay=0)

    elif choice == "insp":
        statements = [
            "You got this!",
            "I believe in you!",
            "You do contribute to society!",
            "You are loved!",
        ]
        print(random.choice(statements))

    elif choice == "quit":
        for i in range(2):
            print("\rQuitting.", end="", flush=True)
            time.sleep(0.4)
            print("\rQuitting..", end="", flush=True)
            time.sleep(0.4)
            print("\rQuitting...", end="", flush=True)
            time.sleep(0.4)
        running = False

    elif choice == "hash":
        message = input("Input: ")
        message_bytes = message.encode("utf-8")
        hex_digest = hashlib.sha512(message_bytes).hexdigest()
        print(f"Original string: {message}")
        print(f"SHA-512 hash: {hex_digest}")

    elif choice == "vert":
        expected = input("Verification hash: ")
        message = input("Message to hash: ")
        hex_digest = hashlib.sha512(message.encode("utf-8")).hexdigest()
        if hex_digest == expected:
            print("Verified")
        else:
            print("Invalid hash")

    elif choice == "ace":
        # Encryption submenu — delegate to aes_cbc if available
        if file_encrypt is None:
            print("Crypto module not available. Ensure aes_cbc.py is present and importable.")
            continue
        sub = input("Choose: (encrypt/decrypt/selftest) ").strip().lower()
        if sub == "encrypt":
            key_in = input("Key (hex or path to key file): ").strip()
            infile = input("Input file path: ").strip()
            outfile = input("Output file path: ").strip()
            # warn if input file missing or empty
            if not os.path.exists(infile):
                print(f"Input file not found: {infile}")
                continue
            try:
                if os.path.getsize(infile) == 0:
                    ans = input("Input file appears empty. Save the file and press Enter to cancel, or type 'y' to proceed anyway: ").strip().lower()
                    if ans != 'y':
                        print("Canceled.")
                        continue
            except OSError:
                print("Unable to read input file size. Proceeding cautiously.")
            try:
                key = parse_key(key_in)
                file_encrypt(key, infile, outfile)
                print(f"Encrypted {infile} -> {outfile} (IV prepended)")
            except Exception as e:
                print(f"Error during encryption: {e}")
        elif sub == "decrypt":
            key_in = input("Key (hex or path to key file): ").strip()
            infile = input("Input file path: ").strip()
            outfile = input("Output file path: ").strip()
            # warn if input file missing or empty
            if not os.path.exists(infile):
                print(f"Input file not found: {infile}")
                continue
            try:
                if os.path.getsize(infile) == 0:
                    ans = input("Input file appears empty. Save the file and press Enter to cancel, or type 'y' to proceed anyway: ").strip().lower()
                    if ans != 'y':
                        print("Canceled.")
                        continue
            except OSError:
                print("Unable to read input file size. Proceeding cautiously.")
            try:
                key = parse_key(key_in)
                file_decrypt(key, infile, outfile)
                print(f"Decrypted {infile} -> {outfile}")
            except Exception as e:
                print(f"Error during decryption: {e}")
        elif sub == "selftest":
            try:
                run_selftest()
            except Exception as e:
                print(f"Self-test failed: {e}")
        else:
            print("Unknown option. Choose encrypt, decrypt, or selftest.")

    elif choice == "keygen":
        if keygen_available:
            # run keygen interactive prompt
            try:
                quasar_keygen.interactive()
            except Exception as e:
                print(f"Keygen failed: {e}")
        else:
            print("Key generator module not available. Run `python3 quasar_keygen.py` instead.")

    else:
        print('Unknown command. Type "help" for the list of commands.')
