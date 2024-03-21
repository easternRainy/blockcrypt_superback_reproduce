from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Util.Padding import pad, unpad

class ShamirBackup:
    def __init__(self, n, m):
        assert 0 < n <= m
        self.n = n
        self.m = m
        self.key = get_random_bytes(16)
    
    def load_data(self, data):
        # data must be binaries
        self.data = data

    def backup(self):
        shares = Shamir.split(self.n, self.m, self.key)

        iv = get_random_bytes(16)
        data_cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        
        padded_data = pad(self.data, AES.block_size)
        data_enciphered = data_cipher.encrypt(padded_data)

        results = []
        for idx, share in shares:
            # idx 16 bytes | share 16 bytes | iv 16 bytes | encrypted data |
            padded_idx = idx.to_bytes(16, byteorder="big")
            result = padded_idx + share + iv + data_enciphered
            results.append(result)

        # print(all([result[32:] == results[0][32:] for result in results]))
        # input()
        return results

    def recover(self, backups):
        assert len(backups) >= self.n
        
        idxs = [int.from_bytes(backup[:16], byteorder="big") for backup in backups]

        shares = [backup[16:32] for backup in backups]
        key_shares = [(idx, share) for idx, share in zip(idxs, shares)]
        restored_key = Shamir.combine(key_shares)
        
        assert all(backup[32:] == backups[0][32:] for backup in backups)
        iv = backups[0][32:48]
        encrypted_data = backups[0][48:]

        data_cipher = AES.new(restored_key, AES.MODE_CBC, iv=iv)
        # data_decrypted = data_cipher.decrypt(encrypted_data)
        data_decrypted = unpad(data_cipher.decrypt(encrypted_data), AES.block_size)

        return data_decrypted

