from blockcrypt import *
import hmac
import hashlib
import base64
import pytest

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

def test_length_after_message_encryption():
    for i in range(10000):
        msg = Message("a" * i)
        encrypted_message = msg.encrypt(keys[0])
        assert len(encrypted_message) <= msg.approximate_data_len_after_encryption()


def test_encrypt_decrypt_header():
    header = Header(10000000000000, 200)
    encrypted_header = header.encrypt(keys[0], referenceIv)
    decrypted_header = encrypted_header.decrypt(keys[0], referenceIv)
    assert header == decrypted_header


def test_invalid_blocks():
    # no secret
    block = Block([], insecure_kdf)
    with pytest.raises(Exception) as e:
        encrypted_block = block.encrypt()
        assert str(e.value).endswith("There is no secret.")
    
    # secret is invalid
    message = Message("")
    passphrase = Passphrase("abc")
    secret = Secret(message, passphrase)
    block = Block([secret], insecure_kdf)
    with pytest.raises(Exception) as e:
        encrypted_block = block.encrypt()
        assert str(e.value).endswith(f"The secret {secret} is not valid.")

    # invalid header len
    block = Block(secrets, insecure_kdf, 7)
    with pytest.raises(Exception) as e:
        encrypted_block = block.encrypt()
        assert "headers should be divided" in str(e.value)

    # invalid data len
    block = Block(secrets, insecure_kdf, 200)
    with pytest.raises(Exception) as e:
        encrypted_block = block.encrypt()
        assert "headers should be divided" in str(e.value)


def test_encrypt_decrypt_block():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    encrypted_block.set_kdf(insecure_kdf)
    decrypted_block = encrypted_block.decrypt(passphrases)
    assert block == decrypted_block


def test_decrypt_block_one_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    valid_passphrases = [passphrases[0], Passphrase("999"), Passphrase("9888"), Passphrase("666")]
    encrypted_block.set_kdf(insecure_kdf)
    decrypted_block = encrypted_block.decrypt(passphrases)
    valid_message = encrypted_block.decrypt_and_show_message_only(passphrases)
    assert valid_message == messages[0].get_data()

def test_decrypt_block_zero_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()

    invalid_passphrases = [Passphrase("123"), Passphrase("999"), Passphrase("9888"), Passphrase("666")]
    encrypted_block.set_kdf(insecure_kdf)
    decrypted_block = encrypted_block.decrypt(invalid_passphrases)
    invalid_message = encrypted_block.decrypt_and_show_message_only(invalid_passphrases)
    assert invalid_message == "Password Incorrect"

def test_decrypt_block_second_valid_passphrase():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    valid_passphrases = [Passphrase("123"), passphrases[1], Passphrase("9888"), Passphrase("666")]
    encrypted_block.set_kdf(insecure_kdf)
    decrypted_block = encrypted_block.decrypt(valid_passphrases)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_passphrases)
    assert valid_message == messages[1].get_data()

def test_decrypt_block_two_valid_passphrases():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()

    valid_passphrases = [Passphrase("123"), passphrases[1], passphrases[2], Passphrase("666")]
    encrypted_block.set_kdf(insecure_kdf)
    decrypted_block = encrypted_block.decrypt(valid_passphrases)
    valid_message = encrypted_block.decrypt_and_show_message_only(valid_passphrases)
    assert valid_message == messages[1].get_data()

def test_encrypt_decrypt_block_secure_kdf():
    block = Block(secrets, secure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    encrypted_block.set_kdf(secure_kdf)
    decrypted_block = encrypted_block.decrypt(passphrases)
    assert block == decrypted_block

def test_very_long_message():
    very_long_message = Message("a" * MAX_DATA_LEN)
    pswd_for_long_msg = Passphrase("password for the long message")
    tmp_messages = [very_long_message, messages[1], messages[2]]
    tmp_passphrases = [pswd_for_long_msg, passphrases[1], passphrases[2]]
    tmp_secrets = [Secret(message, passphrase) for message, passphrase in zip(tmp_messages, tmp_passphrases)]
    tmp_keys = [passphrase.derive_key(insecure_kdf, referenceSalt) for passphrase in tmp_passphrases]
    block = Block(tmp_secrets, insecure_kdf)

    with pytest.raises(Exception) as e:
        encrypted_block = block.encrypt()
        assert str(e.value).endswith("is too long.")


if __name__ == "__main__":    
    test_encrypt_decrypt_message()
    test_length_after_message_encryption()
    test_encrypt_decrypt_header()
    test_invalid_blocks()
    test_encrypt_decrypt_block()
    test_decrypt_block_one_valid_passphrase()
    test_decrypt_block_zero_valid_passphrase()
    test_decrypt_block_second_valid_passphrase()
    test_decrypt_block_two_valid_passphrases()
    test_encrypt_decrypt_block_secure_kdf()
    test_very_long_message()
