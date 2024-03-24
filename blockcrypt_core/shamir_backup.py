from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Util.Padding import pad, unpad

from blockcrypt_core.crypto import *

class ShamirBackup:
    def __init__(self, n, m):
        assert 0 < n <= m
        self.n = n
        self.m = m
        self.key = get_random_bytes(KEY_SIZE)
    
    def load_data(self, data):
        # data must be binaries
        self.data = data

    def backup(self):
        shares = Shamir.split(self.n, self.m, self.key)

        iv = get_random_bytes(CBC_IV_SIZE)
        data_cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        
        padded_data = pad(self.data, AES.block_size)
        data_enciphered = data_cipher.encrypt(padded_data)

        results = []
        for idx, share in shares:
            # idx 16 bytes | share 16 bytes | iv 16 bytes | encrypted data |
            padded_idx = idx.to_bytes(INT_PAD_SIZE, byteorder="big")
            result = padded_idx + share + iv + data_enciphered
            results.append(result)

        return results

    def recover(self, backups):
        assert len(backups) >= self.n
        
        idxs = [int.from_bytes(backup[:INT_PAD_SIZE], byteorder="big") for backup in backups]

        # 16, 32
        share_start = INT_PAD_SIZE
        share_end = share_start + KEY_SIZE
        shares = [backup[INT_PAD_SIZE:share_end] for backup in backups]
        key_shares = [(idx, share) for idx, share in zip(idxs, shares)]
        restored_key = Shamir.combine(key_shares)
        
        # 32, 48
        iv_start = share_end
        iv_end = iv_start + CBC_IV_SIZE
        assert all(backup[iv_start:] == backups[0][iv_start:] for backup in backups)
        iv = backups[0][iv_start:iv_end]

        # 48
        data_start = iv_end
        encrypted_data = backups[0][data_start:]

        data_cipher = AES.new(restored_key, AES.MODE_CBC, iv=iv)
        data_decrypted = unpad(data_cipher.decrypt(encrypted_data), AES.block_size)

        return data_decrypted

