from blockcrypt import *
import hmac
import hashlib
import base64
from crypto import *

from test_utils import *



# def test_gets_data_lengh_of_secret_1_as_string():
#     data_len = get_data_length(messages[0].encode())
#     # print(data_len)
#     assert data_len == 184

# def confirm_block_matches_references():
#     block_cipher = BlockEncrypt(secrets, insecure_kdf, 64, None, referenceSalt, referenceIv)
#     block = block_cipher.encrypt()
#     assert block.salt == referenceSalt
#     assert block.iv == referenceIv
#     assert len(block.data) == 384

#     block_decipher = BlockDecrypt(block, insecure_kdf)
#     block_decipher.decrypt(passphrases[3])

def test_encrypt_decrypt_message():
    
    encrypted_message = messages[0].encrypt(keys[0])
    print(encrypted_message)

    decrypted_message = encrypted_message.decrypt(keys[0])
    print(decrypted_message)

def test_encrypt_decrypt_header():
    header = Header(100, 200)
    print(header)
    encrypted_header = header.encrypt(keys[0], referenceIv)
    print(encrypted_header)

    decrypted_header = encrypted_header.decrypt(keys[0], referenceIv)
    print(decrypted_header)

def test_encrypt_decrypt_headers():
    headers = Headers([Header(0,100), Header(150, 50), Header(300, 400)])
    encrypted_headers = headers.encrypt(keys, referenceIv)
    print(encrypted_headers)
    decrypted_headers = encrypted_headers.decrypt(keys, referenceIv)
    print(decrypted_headers)

def test_encrypt_decrypt_secrets():
    data_starts = [100, 300, 500, 700]
    encrypted_secrets = secrets.encrypt(keys, referenceIv)
    print(encrypted_secrets)

    decrypted_secrets = encrypted_secrets.decrypt(keys, referenceIv)
    print(decrypted_secrets)

def test_encrypt_decrypt_block():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    print(block)
    encrypted_block = block.encrypt()
    print(encrypted_block)
    decrypted_block = encrypted_block.decrypt(keys)
    print(decrypted_block)

def test_decrypt_block_one_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    # print(block)
    encrypted_block = block.encrypt()
    # print(encrypted_block)

    valid_passphrases = [passphrases[0], Passphrase("999"), Passphrase("9888"), Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    print(valid_message)

def test_decrypt_block_zero_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    # print(block)
    encrypted_block = block.encrypt()
    # print(encrypted_block)

    valid_passphrases = [Passphrase("123"), Passphrase("999"), Passphrase("9888"), Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    print(valid_message)

def test_decrypt_block_second_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    # print(block)
    encrypted_block = block.encrypt()
    # print(encrypted_block)

    valid_passphrases = [Passphrase("123"), passphrases[1], Passphrase("9888"), Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    print(valid_message)

def test_decrypt_block_two_valid_passphrases():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()

    valid_passphrases = [Passphrase("123"), passphrases[1], passphrases[2], Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    print(valid_message)

def test_encrypt_decrypt_block_secure_kdf():
    print("Using secure KDF")
    block = Block(secrets, secure_kdf, 64, 1024, referenceSalt, referenceIv)
    print(block)
    encrypted_block = block.encrypt()
    print(encrypted_block)
    decrypted_block = encrypted_block.decrypt(keys)
    print(decrypted_block)


if __name__ == "__main__":
    # insecure_kdf(passphrases[0].encode(), referenceSalt)
    # test_gets_data_lengh_of_secret_1_as_string()
    # confirm_block_matches_references()
    
    # test_encrypt_decrypt_message()
    # test_encrypt_decrypt_header()
    # test_encrypt_decrypt_block()

    # test_decrypt_block_one_valid_passphrase()
    # test_decrypt_block_zero_valid_passphrase()
    # test_decrypt_block_second_valid_passphrase()
    test_encrypt_decrypt_block_secure_kdf()
