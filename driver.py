from blockcrypt import *
from blockcrypt_test import *
import qrcode
import argparse

"""
python3 driver.py encrypt \
--kdf "argon2id" \
--time_cost 5 \
--memory_cost 7 \
--parallelism 4 \
--message "message 1" \
--passphrase "passphrase 1" \
--mesasge "message 2" \
--auto_eff 5 \
--message "message 3" \
--auto eff 7 \
--threshold 3 \
--total_split 9

python3 driver.py decrypt \
--passphrase "passphrase 1"
--qrcode "path/to/qr1.png"
--qrcode "path/to/qr2.png"
--qrcode "path/to/qr3.png"

"""

def main():
    secrets = []

    while True:
        print("input message")
        message = input()

        if message == "exit":
            break

        print("input password")
        passphrase = input()

        secret = Secret(Message(message), Passphrase(passphrase))
        secrets.append(secret)

    header_len = AES.block_size * len(secrets)
    data_len = 4096
    block = Block(secrets, insecure_kdf, header_len, data_len, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()

    # encrypted_block.generate_qrcode()

    compact = encrypted_block._compact()

    recovered = parse_compact_encrypted_block(compact)

    with open("encrypted_block.txt", "w") as f:
        f.write(compact.hex())

    # print("input password to show message")

    # passphrase = input()
    # valid_passphrases = [Passphrase(passphrase)] * len(secrets)
    # valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]

    # valid_message = recovered.decrypt_and_show_message_only(valid_keys)

    # print("The message is:")
    # print(valid_message)


if __name__ == "__main__":
    main()