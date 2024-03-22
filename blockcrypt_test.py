from blockcrypt import *
import hmac
import hashlib
import base64

from crypto import *
from test_utils import *

messages = [
    Message("trust vast puppy supreme public course output august glimpse reunion kite rebel virus tail pass enhance divorce whip edit skill dismiss alpha divert ketchup"),
    Message("this is a test\nyo"),
    Message("yo"),
    Message("what up bro")
]

passphrases = [
    Passphrase("lip gift name net sixth"),
    Passphrase("grunt daisy chow barge pants"),
    Passphrase("decor gooey wish kept pug"),
    Passphrase("holy shit")
]

secrets = [Secret(message, passphrase) for message, passphrase in zip(messages, passphrases)]
keys = [passphrase.derive_key(insecure_kdf, referenceSalt) for passphrase in passphrases]

def test_encrypt_decrypt_message():
    encrypted_message = messages[0].encrypt(keys[0])
    decrypted_message = encrypted_message.decrypt(keys[0])
    assert messages[0] == decrypted_message

def test_encrypt_decrypt_header():
    header = Header(100, 200)
    encrypted_header = header.encrypt(keys[0], referenceIv)
    decrypted_header = encrypted_header.decrypt(keys[0], referenceIv)
    assert header == decrypted_header


def test_encrypt_decrypt_block():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    decrypted_block = encrypted_block.decrypt(keys)
    for s1, s2 in zip(block.secrets, decrypted_block.secrets):
        assert s1.message == s2.message
    

def test_decrypt_block_one_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    valid_passphrases = [passphrases[0], Passphrase("999"), Passphrase("9888"), Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    assert valid_message == messages[0].get_data()

def test_decrypt_block_zero_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()

    valid_passphrases = [Passphrase("123"), Passphrase("999"), Passphrase("9888"), Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    assert valid_message == "Password Incorrect"

def test_decrypt_block_second_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    valid_passphrases = [Passphrase("123"), passphrases[1], Passphrase("9888"), Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    assert valid_message == messages[1].get_data()

def test_decrypt_block_two_valid_passphrases():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()

    valid_passphrases = [Passphrase("123"), passphrases[1], passphrases[2], Passphrase("666")]
    valid_keys = [valid_passphrase.derive_key(insecure_kdf, referenceSalt) for valid_passphrase in valid_passphrases]
    decrypted_block = encrypted_block.decrypt(valid_keys)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_keys)
    assert valid_message == messages[1].get_data()

def test_encrypt_decrypt_block_secure_kdf():
    block = Block(secrets, secure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    decrypted_block = encrypted_block.decrypt(keys)
    for s1, s2 in zip(block.secrets, decrypted_block.secrets):
        assert s1.message == s2.message


if __name__ == "__main__":
    
    test_encrypt_decrypt_message()
    test_encrypt_decrypt_header()
    test_encrypt_decrypt_block()

    test_decrypt_block_one_valid_passphrase()
    test_decrypt_block_zero_valid_passphrase()
    test_decrypt_block_second_valid_passphrase()
    test_decrypt_block_two_valid_passphrases()
    test_encrypt_decrypt_block_secure_kdf()
