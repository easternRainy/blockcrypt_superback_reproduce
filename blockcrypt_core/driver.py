from blockcrypt_core.blockcrypt import *
from blockcrypt_core.blockcrypt_test import *
from blockcrypt_core.shamir_backup import *
from blockcrypt_core.qr_code import *
import argparse
import os

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

class CliDriver:

    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Backup your most important secrets with plausible deniability..")
        self.add_arguments()

    def add_arguments(self):
        self.parser.add_argument("command", choices=["encrypt", "decrypt"], help="Command to execute.")
        self.parser.add_argument("--message", action="append", help="Messages to encrypt or decrypt.")
        self.parser.add_argument("--passphrase", action="append", choices=["userinput", "eff"], help="Passphrase for encryption or decryption.")
        # self.parser.add_argument("--passphrase", action="append", help="Passphrase for encryption or decryption.")

        # self.parser.add_argument("--auto_eff", type=int, help="Auto efficiency setting.")
        self.parser.add_argument("--save_path", type=str, help="Paths to save QR code images when encryption.")
        self.parser.add_argument("--qrcode", action="append", help="Paths to QR code images for decryption.")

        self._add_kdf_args()
        self._add_shamir_args()

    def _add_kdf_args(self):
        self._add_argon2id_args()

    def _add_argon2id_args(self):
        self.parser.add_argument("--kdf", type=str, default="argon2id", choices=["argon2id"], help="Key Derivation Function.")
        self.parser.add_argument("--time_cost", type=int, default=3, help="Time cost for the KDF.")
        self.parser.add_argument("--memory_cost", type=int, default=65536, help="Memory cost for the KDF.")
        self.parser.add_argument("--parallelism", type=int, default=4, help="Parallelism factor for the KDF.")

    def _add_shamir_args(self):
        self.parser.add_argument("--threshold", type=int, help="Threshold for operation.")
        self.parser.add_argument("--total_split", type=int, help="Total number of splits.")


    def parse_args_and_verify(self):
        args = self.parser.parse_args()
        assert len(args.message) == len(args.passphrase)
        assert 0 < args.threshold < args.total_split

        if args.kdf == "argon2id":
            assert args.time_cost > 0 and args.memory_cost > 0 and args.parallelism > 0

        return args


def create_secrets_from_args(args):

    secrets = []
    for m, p_mode in zip(args.message, args.passphrase):
        if p_mode == "userinput":
            print(f"Please enter the passphrase for {m}")
            p = input()
            print(p)

        elif p_mode == "eff":
            p = os.urandom(16).hex()
            print(f"Here is the passphrase for {m}: {p}")

        message = Message(m)
        passphrase = Passphrase(p)
        secret = Secret(message, passphrase)
        secrets.append(secret)

    return secrets

 

def main():
    cli = CliDriver()
    args = cli.parse_args_and_verify()


    if args.command == "encrypt":
        kdf = secure_kdf
        secrets = create_secrets_from_args(args)
        block = Block(secrets, kdf)
        encrypted_block = block.encrypt()
        shamir_backup = ShamirBackup(args.threshold, args.total_split)
        shamir_backup.load_data(encrypted_block.get_encrypted_data())
        backups = shamir_backup.backup()
        for i, backup in enumerate(backups):
            generate_qr_code(backup, save_path=f"{args.save_path}/qr_code_{i}.png")

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