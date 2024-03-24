from blockcrypt_core.blockcrypt import *
from blockcrypt_core.blockcrypt_test import *
from blockcrypt_core.shamir_backup import *
from blockcrypt_core.qr_code import *
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
    parser = argparse.ArgumentParser(description="Backup your most important secrets with plausible deniability..")
    parser.add_argument("command", choices=["encrypt", "decrypt"], help="Command to execute.")
    parser.add_argument("--kdf", type=str, help="Key Derivation Function.")
    parser.add_argument("--time_cost", type=int, help="Time cost for the KDF.")
    parser.add_argument("--memory_cost", type=int, help="Memory cost for the KDF.")
    parser.add_argument("--parallelism", type=int, help="Parallelism factor for the KDF.")
    parser.add_argument("--message", action="append", help="Messages to encrypt or decrypt.")
    # parser.add_argument("--passphrase-flag", action="append", choices=["userinput", "eff"], help="Passphrase for encryption or decryption.")
    parser.add_argument("--passphrase", action="append", help="Passphrase for encryption or decryption.")

    parser.add_argument("--auto_eff", type=int, help="Auto efficiency setting.")
    parser.add_argument("--threshold", type=int, help="Threshold for operation.")
    parser.add_argument("--total_split", type=int, help="Total number of splits.")
    parser.add_argument("--qrcode", action="append", help="Paths to QR code images for decryption.")

    args = parser.parse_args()

    if args.command == "encrypt":
        print(args.passphrase_flag)
        input()
        kdf = secure_kdf
        assert len(args.message) == len(args.passphrase)
        messages = [Message(m) for m in args.message]
        passphrases = [Passphrase(p) for p in args.passphrase]
        secrets = [Secret(m, p) for m, p in zip(messages, passphrases)]
        block = Block(secrets, kdf)
        encrypted_block = block.encrypt()
        shamir_backup = ShamirBackup(args.threshold, args.total_split)
        shamir_backup.load_data(encrypted_block.get_encrypted_data())
        backups = shamir_backup.backup()
        for i, backup in enumerate(backups):
            generate_qr_code(backup, save_path=f"assets/qr_code_{i}.png")

        print("QR Code generated")

    if args.command == "decrypt":
        kdf = secure_kdf
        passphrases = [Passphrase(p) for p in args.passphrase]
        
        n_qr = len(args.qrcode)
        shamir_recover = ShamirBackup(n_qr, n_qr)

        qr_codes_data = [read_qr_code(p) for p in args.qrcode]

        recovered_encrypted_block = shamir_recover.recover(qr_codes_data)
        encrypted_block = parse_compact_encrypted_block(recovered_encrypted_block)
        encrypted_block.set_kdf(secure_kdf)
        decrypted_message = encrypted_block.decrypt_for_user(passphrases[0])
        print(decrypted_message)
                



if __name__ == "__main__":
    main()