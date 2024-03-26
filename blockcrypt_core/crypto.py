from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import base64
import secrets
from pathlib import Path
from password_strength import PasswordStats
import zxcvbn

# some constants
B64_PAD_UNIT = 4
B64_PAD = "="
GCM_IV_SIZE = 12 # bytes
SALT_SIZE = 16 # bytes
AUTH_TAG_SIZE = 16
CBC_IV_SIZE = 16 # bytes
KEY_SIZE = 16 # bytes
INT_PAD_SIZE = 16
BLOCK_HEADER_SPLIT = ":"
HEADER_SIZE = 16
ARGON_SPLIT = "$"
MAX_DATA_LEN = 2**32
INT_PAD_SIZE = 8 # bytes
CONTAINER_SIZE = 256
LEAST_PASSWORD_STRENGTH = 0.7
SECONDS_PER_YEAR = 365 * 24 * 3600
MIN_YEAR_CRACK = 100

def secure_kdf(passphrase, salt):
    # ph = PasswordHasher(time_cost=5, memory_cost=2**20)
    ph = PasswordHasher()
    hash_str = ph.hash(passphrase, salt=salt)
    hash_bytes = argon_hash_str_to_bytes(hash_str)
    return hash_bytes
    

def argon_hash_str_to_bytes(hash_str):
    hash_b64 = hash_str.split(ARGON_SPLIT)[-1]
    missing_padding = len(hash_b64) % B64_PAD_UNIT
    if missing_padding:
        hash_b64 += B64_PAD * (B64_PAD_UNIT - missing_padding)
    hash_bytes = base64.b64decode(hash_b64)

    return hash_bytes


def generate_random_eff_passphrase(n, sep=" "):
    curr_path = Path(__file__).resolve()
    with open(f"{curr_path.parent}/assets/eff_large_wordlist.txt", "r") as f:
        lines = f.read().split("\n")
    table = dict()
    for line in lines:
        if not line:
            continue
        idx, word = line.split("\t")
        table[idx] = word

    toss = ["1", "2", "3", "4", "5", "6"]
    def take_five_tosses():
        return "".join([secrets.choice(toss) for _ in range(5)])
    ids = [take_five_tosses() for _ in range(n)]
    passphrases = [table[i] for i in ids]
    return sep.join(passphrases)


def is_strong_password(password):
    # 1. Use password_strength
    stats = PasswordStats(password)
    if stats.strength() < 0.7:
        return False

    # 2. Use zxcvbn
    results = zxcvbn.zxcvbn(password)
    years = results["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"] / SECONDS_PER_YEAR

    if years < MIN_YEAR_CRACK:
        return False

    return True



class KDF:
    def export(self):
        return "Not implemented."


if __name__ == "__main__":
    for i in range(10):
        p = generate_random_eff_passphrase(3)
        print(is_strong_password(p))
