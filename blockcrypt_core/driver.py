from blockcrypt_core.blockcrypt import *
from blockcrypt_core.blockcrypt_test import *
from blockcrypt_core.shamir_backup import *
from blockcrypt_core.qr_code import *
from blockcrypt_core.crypto import generate_random_eff_passphrase
import argparse
import os
import logging
import getpass
from collections import deque


class CliDriver:

    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Backup your most important secrets with plausible deniability..")
        self.add_arguments()

    def add_arguments(self):
        self.parser.add_argument("command", choices=["encrypt", "decrypt"], help="Command to execute.")
        self.parser.add_argument("--message", action="append", help="Messages to encrypt or decrypt.")
        self.parser.add_argument("--pass_mode", action="append", choices=["userinput", "eff", "terminal"], help="Passphrase for encryption or decryption.")
        self.parser.add_argument("--passphrase", action="append", help="Passphrase for encryption or decryption.")

        self.parser.add_argument("--save_path", type=str, help="Paths to save QR code images when encryption.")
        self.parser.add_argument("--qrcode", action="append", help="Paths to QR code images for decryption.")

        self._add_eff_args()
        self._add_kdf_args()
        self._add_shamir_args()

    def _add_eff_args(self):
        self.parser.add_argument("--n_words", type=int, default=5, help="The number of words in EFF passphrase.")
        self.parser.add_argument("--separator", type=str, default=" ", help="The separator of words in EFF passphrase.")

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

        if args.command == "encrypt":
            assert len(args.message) == len(args.pass_mode)
            assert 0 < args.threshold < args.total_split
            assert args.n_words >= 5

            n = sum([1 if m == "terminal" else 0 for m in args.pass_mode])
            if  n > 0 and len(args.passphrase) != n:
                raise Exception("Not enough passphrases provided through terminal.")

        if args.command == "decrypt":
            if len(args.passphrase) > 1:
                raise Exception("Too many passphrases in decrypt mode.")

        if args.kdf == "argon2id":
            assert args.time_cost > 0 and args.memory_cost > 0 and args.parallelism > 0

        return args


def get_password_from_userinput():
    try:
        max_loop = 3
        for i in range(max_loop):
            p = getpass.getpass(f"Please enter the passphrase: ")
            p_verify = getpass.getpass(f"Please verify the passphrase.")
            if p == p_verify:
                break
            else:
                logging.warning("Passwords does not match")
        
        if p != p_verify:
            raise Exception(f"Too many trials.")
        
    except:
        raise Exception("Password was not successfully entered.")
    else:
        logging.info("Password entered successfully.")

    return p



def create_secrets_from_args(args):

    secrets = []
    pass_dq = deque(args.passphrase)
    for m, p_mode in zip(args.message, args.pass_mode):
        if p_mode == "userinput":
            p = get_password_from_userinput()
        elif p_mode == "eff":
            p = generate_random_eff_passphrase(args.n_words, args.separator)
            logging.info(f"Here is the passphrase for {m}:\n{p}")

        elif p_mode == "terminal":
            p = pass_dq.popleft()

        message = Message(m)
        passphrase = Passphrase(p)
        secret = Secret(message, passphrase)
        secrets.append(secret)

    return secrets

 

def main():
    cli = CliDriver()
    args = cli.parse_args_and_verify()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


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

        logging.info("QR Code generated")

    if args.command == "decrypt":
        kdf = secure_kdf
        passphrases = [Passphrase(p) for p in args.passphrase]

        n_qr = len(args.qrcode)
        shamir_recover = ShamirBackup(n_qr, n_qr)

        qr_codes_data = [read_qr_code(p) for p in args.qrcode]

        try:
            recovered_encrypted_block = shamir_recover.recover(qr_codes_data)
        except:
            raise Exception("The QR codes provided are not enough to decrypt the message.")
        encrypted_block = parse_compact_encrypted_block(recovered_encrypted_block)
        encrypted_block.set_kdf(secure_kdf)
        decrypted_message = encrypted_block.decrypt_for_user(passphrases[0])
        logging.info(decrypted_message)
                



if __name__ == "__main__":
    main()

