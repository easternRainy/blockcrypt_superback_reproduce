from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import base64
from test_utils import *

def secure_kdf(passphrase, salt):
    # ph = PasswordHasher(time_cost=5, memory_cost=2**20)
    ph = PasswordHasher()
    hash_str = ph.hash(passphrase, salt=salt)
    hash_bytes = argon_hash_str_to_bytes(hash_str)
    return hash_bytes
    

def argon_hash_str_to_bytes(hash_str):
    hash_b64 = hash_str.split("$")[-1]
    missing_padding = len(hash_b64) % 4
    if missing_padding:
        hash_b64 += "=" * (4 - missing_padding)
    hash_bytes = base64.b64decode(hash_b64)

    return hash_bytes


if __name__ == "__main__":
    secure_kdf("abcdef", referenceSalt)
