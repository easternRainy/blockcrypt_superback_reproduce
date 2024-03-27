from blockcrypt_core.blockcrypt import *
from blockcrypt_core.blockcrypt_test import *
from blockcrypt_core.shamir_backup import *
from blockcrypt_core.qr_code import *
from blockcrypt_core.crypto import generate_random_eff_passphrase
import argparse
import os
import logging
import getpass
from collections import deque, defaultdict
import base64


class CliDriver:

    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Backup your most important secrets with plausible deniability..")
        self.add_arguments()

    def add_arguments(self):
        self.parser.add_argument("command", choices=["encrypt", "decrypt"], help="Command to execute.")
        self._add_encrypt_args()
        self._add_decrypt_args()


    def _add_encrypt_args(self):
        self.parser.add_argument("--msg_mode", action="append", choices=["userinput", "terminal", "from_file"], help="How to provide the message to the terminal.")
        self.parser.add_argument("--message", action="append", help="Messages to encrypt or decrypt.")
        self.parser.add_argument("--msg_from_file", action="append", help="Messages from path/to/file.")
        self.parser.add_argument("--pass_mode", action="append", required=True, choices=["userinput", "eff", "terminal"], help="Passphrase for encryption or decryption.")
        self.parser.add_argument("--passphrase", action="append", help="Passphrase for encryption or decryption.")
        self.parser.add_argument("--enc_file_mode", choices=["qrcode", "binary"], default="qrcode", help="Encrypted files format, QR code or binary file.")
        self.parser.add_argument("--save_path", type=str, help="Paths to save QR codes or binary files after encryption.")
        self._add_eff_args()
        self._add_kdf_args()
        self._add_shamir_args()

    def _add_decrypt_args(self):
        self.parser.add_argument("--qrcode", action="append", help="Paths to QR code images for decryption.")
        self.parser.add_argument("--enc_file", action="append", help="Paths to encrypted binary files for decryption.")

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
        self.parser.add_argument("--threshold", type=int, default=3, help="Threshold for operation.")
        self.parser.add_argument("--total_split", type=int, default=5, help="Total number of splits.")

    def _verify_modes(self, args):
        # If there are n --pass_mode "terminal", we hope that there are n --passphrases "pass phrase"
        
        msg_table = defaultdict(int)
        if args.msg_mode:
            for m_mode in args.msg_mode:
                msg_table[m_mode] += 1

        pass_table = defaultdict(int)
        if args.pass_mode:
            for p_mode in args.pass_mode:
                pass_table[p_mode] += 1


        if args.command == "encrypt":
            assert msg_table["terminal"] == (len(args.message) if args.message else 0)
            assert msg_table["from_file"] == (len(args.msg_from_file) if args.msg_from_file else 0)
            assert pass_table["terminal"] == (len(args.passphrase) if args.passphrase else 0)

        if args.command == "decrypt":
            assert len(args.pass_mode) == 1
            assert args.pass_mode[0] in ["userinput", "terminal"]
            assert pass_table["terminal"] == (len(args.passphrase) if args.passphrase else 0)

        return True




    def parse_args_and_verify(self):
        args = self.parser.parse_args()
        self._verify_modes(args)

        if args.command == "encrypt":
            assert args.msg_mode and args.pass_mode
            assert len(args.msg_mode) == len(args.pass_mode)
            assert 0 < args.threshold < args.total_split
            assert args.n_words >= 5

        if args.command == "decrypt":
            assert (args.enc_file is not None) ^ (args.qrcode is not None)

        if args.kdf == "argon2id":
            assert args.time_cost > 0 and args.memory_cost > 0 and args.parallelism > 0

        return args


def get_msg_from_userinput():
    max_loop = 3
    confirmed = False
    for i in range(max_loop):
        m = input("Please enter the message you want to encrypt:\n")
        confirm = input("Please enter y if the input is finished, or r to re-enter the message:\n")

        if confirm == "y":
            confirmed = True
            return m
        elif confirm == "r":
            continue
        else:
            raise Exception("Invalid input.")

    if not confirmed:
        raise Exception("Too many trials.")
    return None

def get_msg_from_file(file_path):
    # If the file is text, read as text
    # If not, read as binary and convert to base64 text string
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "rb") as f:
            binary_content = f.read()
            b64_str = base64.b64encode(binary_content).decode("utf-8")
            b64_str = b64_pad_multiple_four(b64_str)
            return b64_str

    return None



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

    msg_dq = deque(args.message) if args.message else None
    msg_file_dq = deque(args.msg_from_file) if args.msg_from_file else None
    pass_dq = deque(args.passphrase) if args.passphrase else None

    for m_mode, p_mode in zip(args.msg_mode, args.pass_mode):
        if m_mode == "userinput":
            m = get_msg_from_userinput()
            assert m
        elif m_mode == "terminal":
            assert msg_dq
            m = msg_dq.popleft()
        elif m_mode == "from_file":
            assert msg_file_dq
            file_path = msg_file_dq.popleft()
            m = get_msg_from_file(file_path)
            assert m

        if p_mode == "userinput":
            p = get_password_from_userinput()
        elif p_mode == "eff":
            p = generate_random_eff_passphrase(args.n_words, args.separator)
            logging.info(f"Here is the passphrase for \n\n{m[:100]}{"..." if len(m) > 100 else ""}\n\n{p}\n\nPlease save it to a secure place.")
            confirm = input("Please enter any key to continue")
        elif p_mode == "terminal":
            assert pass_dq
            p = pass_dq.popleft()

        message = Message(m)
        passphrase = Passphrase(p)
        secret = Secret(message, passphrase)
        secrets.append(secret)

    return secrets


def save_backup_files(args, backups):
    # --enc_file_mode", choices=["qrcode", "binary"
    if args.enc_file_mode == "qrcode":
        for i, backup in enumerate(backups):
            generate_qr_code(backup, save_path=f"{args.save_path}/qr_code_{i}.png")

        logging.info("QR Code generated")
    elif args.enc_file_mode == "binary":
        for i, backup in enumerate(backups):
            with open(f"{args.save_path}/enc_file_{i}", "wb") as f:
                f.write(backup)
        logging.info("Successfully generated backup files.")
    else:
        raise Exception("Encryption file mode is wrong.")


def process_decrypted_message(args, decrypted_message):

    try:
        decoded_bytes = base64.b64decode(decrypted_message, validate=True)
        decoded_file = f"{args.save_path}/decrypt_binary"
        with open(decoded_file, "wb") as f:
            f.write(decoded_bytes)
        logging.info(f"The decrypted message is a binary file, saved to {decoded_file}.")
    except:
        logging.info(f"The decrypted message is:\n\n{decrypted_message}\n\n")



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
        save_backup_files(args, backups)


    if args.command == "decrypt":
        kdf = secure_kdf

        passphrases = []
        pass_dq = deque(args.passphrase) if args.passphrase else None
        for p_mode in args.pass_mode:
            if p_mode == "userinput":
                passphrase = getpass.getpass(f"Please enter the passphrase: ")
            elif p_mode == "terminal":
                assert pass_dq
                passphrase = pass_dq.popleft()
            else:
                raise Exception("Passmode is wrong.")
            passphrases.append(Passphrase(passphrase))

        n_data = len(args.qrcode) if args.qrcode else len(args.enc_file)
        shamir_recover = ShamirBackup(n_data, n_data)

        bin_data = []
        if args.qrcode:
            bin_data = [read_qr_code(p) for p in args.qrcode]

        if args.enc_file:
            for b_file in args.enc_file:
                with open(b_file, "rb") as f:
                    data = f.read()
                    bin_data.append(data)



        try:
            recovered_encrypted_block = shamir_recover.recover(bin_data)
        except:
           raise Exception("Password is wrong or the QR codes / binary encrypted files provided are not enough to decrypt the message.")

        encrypted_block = parse_compact_encrypted_block(recovered_encrypted_block)
        encrypted_block.set_kdf(secure_kdf)
        decrypted_message = encrypted_block.decrypt_for_user(passphrases[0])

        process_decrypted_message(args, decrypted_message)


if __name__ == "__main__":
    main()

