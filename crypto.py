from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import base64
from test_utils import *

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


if __name__ == "__main__":
    secure_kdf("abcdef", referenceSalt)
