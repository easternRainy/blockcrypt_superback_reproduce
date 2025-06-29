from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import math
import base64
from blockcrypt_core.crypto import *


class Message:
    def __init__(self, message):
        self.message = message

    def is_valid(self):
        return self.message is not None and len(self.message) > 0

    def encrypt(self, key):
        data_iv = get_random_bytes(GCM_IV_SIZE)
        data_cipher = AES.new(key, AES.MODE_GCM, nonce=data_iv)
        data_enciphered, data_auth_tag = data_cipher.encrypt_and_digest(self.message.encode())

        return EncryptedMessage(data_enciphered, data_iv, data_auth_tag)

    def __str__(self):
        return self.message

    def __len__(self):
        return len(self.message)

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False
        return self.message == other.get_data()

    def get_data(self):
        return self.message

    def approximate_data_len_after_encryption(self):
        # Calculate data length after encryption without really encrypt the data
        result = len(self.message)
        
        result += GCM_IV_SIZE
        result += AUTH_TAG_SIZE
        result = (1 + result // AES.block_size) * AES.block_size
        return result


class EncryptedMessage:
    def __init__(self, data_enciphered, data_iv, data_auth_tag):
        self.data_enciphered = data_enciphered
        self.data_iv = data_iv
        self.data_auth_tag = data_auth_tag

    def decrypt(self, key):
        try:
            data_decipher = AES.new(key, AES.MODE_GCM, nonce=self.data_iv)
            plaintext_data_bytes = data_decipher.decrypt_and_verify(self.data_enciphered, self.data_auth_tag)
            plaintext = plaintext_data_bytes.decode()
            return Message(plaintext)
        except:
            return Message("")

    def __str__(self):
        return f"\n\tencrypted_data: {self.data_enciphered.hex()}\n\tiv: {self.data_iv.hex()}\n\tdata auth tag: {self.data_auth_tag.hex()}"

    def __len__(self):
        return len(self.data_enciphered) + len(self.data_iv) + len(self.data_auth_tag)

    def get_encrypted_data(self):
        return self.data_enciphered + self.data_iv + self.data_auth_tag


class Passphrase:
    def __init__(self, passphrase):
        self.passphrase = passphrase

    def is_valid(self):
        return self.passphrase is not None

    def derive_key(self, kdf, salt):
        key = kdf(self.passphrase.encode(), salt)
        return key

    def __str__(self):
        return self.passphrase

    def __len__(self):
        return len(self.passphrase)

    def get_data(self):
        return self.passphrase


class Header:
    def __init__(self, data_start, data_len):
        self.data_start = data_start
        self.data_len = data_len

    def encrypt(self, key, iv):
        header_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded_header = self.get_data()
        header_enciphered = header_cipher.encrypt(padded_header)

        return EncryptedHeader(header_enciphered)

    def __str__(self):
        return f"{self.data_start}{BLOCK_HEADER_SPLIT}{self.data_len}"

    def __len__(self):
        return len(self.__str__())
    
    def get_data(self):
        return self.data_start.to_bytes(INT_PAD_SIZE, byteorder="big") + self.data_len.to_bytes(INT_PAD_SIZE, byteorder="big")

    def __eq__(self, other):
        if not isinstance(other, Header):
            return False
        return self.data_start == other.data_start and self.data_len == other.data_len


class EncryptedHeader:
    def __init__(self, header_enciphered):
        self.header_enciphered = header_enciphered

    def decrypt(self, key, iv):
        try:
            header_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            header_decrypted = header_cipher.decrypt(self.header_enciphered)
            data_start_bytes, data_end_bytes = header_decrypted[:INT_PAD_SIZE], header_decrypted[INT_PAD_SIZE:2*INT_PAD_SIZE]
            data_start, data_len = int.from_bytes(data_start_bytes, byteorder="big"), int.from_bytes(data_end_bytes, byteorder="big")

            return Header(data_start, data_len)
        except:
            return Header(-1, -1)

    def __str__(self):
        return self.header_enciphered.hex()

    def __len__(self):
        return len(self.header_enciphered)

    def get_encrypted_data(self):
        return self.header_enciphered


class Secret:
    def __init__(self, message: Message, passphrase: Passphrase):
        self.message = message
        self.passphrase = passphrase

    def is_valid(self):
        return self.message.is_valid() and self.passphrase.is_valid()

    def __str__(self):
        result = f"message: {self.message}\npassphrase: {self.passphrase}"
        return result

    def get_message(self):
        return self.message.get_data()

    def get_passphrase(self):
        return self.passphrase.get_data()


class Block:
    def __init__(self, secrets: list[Secret], kdf, headers_len=None, data_len=None, salt=None, iv=None):
        self.secrets = secrets
        self.kdf = kdf
        self.headers_len = headers_len
        self.data_len = data_len

        if not salt: salt = get_random_bytes(SALT_SIZE)
        if not iv: iv = get_random_bytes(CBC_IV_SIZE)

        self.salt = salt
        self.iv = iv

        self.keys = []

    def is_valid(self):
        if not self.secrets:
            raise Exception(f"There is no secret.")

        # All secrets are valid.
        for secret in self.secrets:
            if not secret.is_valid():
                raise Exception(f"The secret {secret} is not valid.")

        # There is no repeated passphrase
        all_passphrases = [s.get_passphrase() for s in self.secrets]
        if len(all_passphrases) > len(set(all_passphrases)):
            raise Exception(f"There are repeated passphrases")

        # All passwords are strong
        for p in all_passphrases:
            if not is_strong_password(p):
                raise Exception(f"The password {p} is weak.")


        # Each header is in the format of start_position (8 bytes) | length (8 bytes).
        # The maximum of start_position is 2^64-1, so is maximum length.
        # If the first header is (0, 2^64-1) then there should be no next header.
        # If the first n headers are (0, 1), (1, 1), (2, 1),..., (2^64-1, 1)
        # So the total length of all secrets should not exceed 2^64-1.
        # For safety concerns, we set it to 2^32, and set the length of each message should not exceed
        # (2^32) / len(secrets)
        max_msg_len = MAX_DATA_LEN // len(self.secrets)
        total_msg_len = 0
        for secret in self.secrets:
            msg_len = secret.message.approximate_data_len_after_encryption()
            if msg_len >= max_msg_len:
                raise Exception(f"The secret {str(secret)[:100]}... is too long.")
            total_msg_len += msg_len

        # If the user set a limit of the header size, make sure it can be divided by 16
        # and can hold the number of secrets
        if self.headers_len:
            if self.headers_len % AES.block_size != 0:
                raise Exception(f"The length of headers should be divided by {AES.block_size}")

            max_headers_n = self.headers_len // HEADER_SIZE
            if len(self.secrets) > max_headers_n:
                raise Exception(f"Too many secrets for header length {self.headers_len}")
        else:
            self.headers_len = len(self.secrets) * HEADER_SIZE

        # If the user set a limit of data size, make sure it can be divided by 16
        # and can hold the secrets
        if self.data_len:
            if self.data_len % AES.block_size != 0:
                raise Exception(f"The length of data should be divided by {AES.block_size}")
            if total_msg_len > self.data_len:
                raise Exception(f"Too long total secret length for data length {self.data_len}")
        else:
            # data length can be changed during encryption, set a default value
            self.data_len = total_msg_len
            
            if self.data_len >= MAX_DATA_LEN:
                raise Exception(f"Total secret length is too long.")

        return True

    def __str__(self):
        result = "------Block start------\n"
        result += f"salt: {self.salt.hex()}\niv: {self.iv.hex()}\nheaders_len: {self.headers_len}\ndata_len: {self.data_len}\n"
        result += "secrets: \n"
        result += "\n".join([str(secret) for secret in self.secrets])
        result += "-----Block end--------\n"
        return result

    def __eq__(self, other):
        if not isinstance(other, Block):
            return False
        
        return all([s1.message == s2.message] for s1, s2 in zip(self.secrets, other.secrets))


    def encrypt(self):
        if not self.is_valid():
            raise Exception("Block is invalid")

        # step 1: dervie keys 
        if not self.keys:
            passphrases = [s.passphrase for s in self.secrets]
            self.keys = derive_keys(self.kdf, self.salt, passphrases)

        # step 2: encrypt data/messages
        messages = [secret.message for secret in self.secrets]
        data_buffers = [message.encrypt(key).get_encrypted_data() for key, message in zip(self.keys, messages)]
        
        # step 3: calculate data_starts index
        data_lengths = [len(data_buffer) for data_buffer in data_buffers]
        
        tmp_sum = 0
        data_starts = [0]
        for data_length in data_lengths[:-1]:
            tmp_sum += data_length
            data_starts.append(tmp_sum)

        # step 4: calcualte headers
        headers = [Header(data_start, len(data_buffer)) for data_start, data_buffer in zip(data_starts, data_buffers)]

        # step 5: encrypt headers
        headers_buffers = [header.encrypt(key, self.iv).get_encrypted_data() for key, header in zip(self.keys, headers)]

        # step 6: add paddings.
        headers_final = self._append_padding(headers_buffers, self.headers_len)
        data_final = self._append_padding(data_buffers, self.data_len)

        return EncryptedBlock(self.salt, self.iv, headers_final, data_final)


    def _append_padding(self, buffers_list, target_len):
        result = b"".join(buffers_list)
        unpadded_len = len(result)
        assert unpadded_len <= target_len
        diff_len = target_len - unpadded_len
        padding = get_random_bytes(diff_len)
        result += padding
        return result


class EncryptedBlock:
    def __init__(self, salt, iv, headers, data):
        self.salt = salt
        self.iv = iv
        self.headers = headers
        self.data = data
        self.keys = []

    def __str__(self):
        result = "------Encrypted Block start------\n"
        result += f"salt: {self.salt.hex()}\niv: {self.iv.hex()}\nheaders: {self.headers.hex()}\ndata: {self.data.hex()}\n"
        result += "------Encrypted Block end------\n"
        return result

    def __eq__(self, other):
        return self.salt == other.salt and self.iv == other.iv and self.headers == other.headers and self.data == other.data

    def set_kdf(self, kdf):
        self.kdf = kdf
    
    def decrypt(self, passphrases):
        assert self.kdf
        if not self.keys:
            self.keys = derive_keys(self.kdf, self.salt, passphrases)
        decrypted_headers = self._decrypt_headers()
        secrets = self._decrypt_data(decrypted_headers)
        valid_secrets = [secret for secret in secrets if secret.is_valid()]
        decrypted_block = Block(valid_secrets, None, len(self.headers), len(self.data), self.salt, self.iv)

        return decrypted_block

    def decrypt_for_user(self, passphrase:Passphrase):
        n = len(self.headers) // AES.block_size
        passphrases = [passphrase] * n
        return self.decrypt_and_show_message_only(passphrases)

    def decrypt_and_show_message_only(self, passphrases):
        decrypted_block = self.decrypt(passphrases)
        return decrypted_block.secrets[0].get_message() if decrypted_block.secrets else "Password Incorrect"

    def _decrypt_headers(self):
        assert self.keys
        headers = self.headers
        assert len(headers) % AES.block_size == 0
        n = len(headers) // AES.block_size

        headers_buffers = [headers[i*AES.block_size:(i+1)*AES.block_size] for i in range(n)]
        encrypted_headers = [EncryptedHeader(header_buffer) for header_buffer in headers_buffers]
        decrypted_headers = [encrypted_header.decrypt(key, self.iv) for key, encrypted_header in zip(self.keys, encrypted_headers)]

        return decrypted_headers

    def _decrypt_data(self, decrypted_headers):
        assert self.keys
        headers = decrypted_headers
        data_buffers_list = [self.data[header.data_start:header.data_start+header.data_len] for header in headers]
        encrypted_messages_list = [self._parse_data_buffer_item(item) for item in data_buffers_list]
        decrypted_messages_list = [encrypted_message.decrypt(key) for encrypted_message, key in zip(encrypted_messages_list, self.keys)]

        placeholder_passphrase = Passphrase("***")
        decrypted_secrets = [Secret(message, placeholder_passphrase) for message in decrypted_messages_list]
 
        return decrypted_secrets

    def _parse_data_buffer_item(self, item):
        # assert len(item) > (12 + 16)
        data_enciphered = item[:-(GCM_IV_SIZE + AUTH_TAG_SIZE)]
        data_iv = item[-(GCM_IV_SIZE + AUTH_TAG_SIZE):-AUTH_TAG_SIZE]
        data_auth_tag = item[-AUTH_TAG_SIZE:]

        return EncryptedMessage(data_enciphered, data_iv, data_auth_tag)

    def _compact(self):
        """
        salt (16 bytes) | iv (16 bytes) | header number (16 bytes) | headers (16 bytes) | data
        """
        header_len = len(self.headers) // AES.block_size
        padded_header_len = header_len.to_bytes(INT_PAD_SIZE, byteorder="big")

        return self.salt + self.iv + padded_header_len + self.headers + self.data

    def get_encrypted_data(self):
        return self._compact()

    def get_salt(self):
        return self.salt


class EncryptedBlockContainer:
    # kdf and parameters 256 bytes | encrypted block (size varies)
    def __init__(self, kdf: KDF, encrypted_block: EncryptedBlock):
        self.kdf = kdf
        self.encrypted_block = encrypted_block

    def patch_kdf_metadata(self):
        kdf_info = KDF.export()
        padded_kdf_info = pad(kdf_info, CONTAINER_SIZE)
        return padded_kdf_info + self.encrypted_block


def parse_compact_encrypted_block(compact_encrypted_block):
    p1 = 0
    p2 = SALT_SIZE # 16
    salt = compact_encrypted_block[p1:p2]
    
    p1 = p2 # 16
    p2 += CBC_IV_SIZE # 32
    iv = compact_encrypted_block[p1:p2]

    p1 = p2 # 32
    p2 += INT_PAD_SIZE # 48
    padded_header_len = compact_encrypted_block[p1:p2]
    header_len = int.from_bytes(padded_header_len, byteorder="big")

    assert header_len >= 0

    p1 = p2
    p2 += header_len * AES.block_size
    headers = compact_encrypted_block[p1:p2]

    p1 = p2
    data = compact_encrypted_block[p2:]

    recovered_encrypted_block = EncryptedBlock(salt, iv, headers, data)

    return recovered_encrypted_block
        
def derive_keys(kdf, salt, passphrases:list[Passphrase]):
    keys = [p.derive_key(kdf, salt) for p in passphrases]
    return keys

