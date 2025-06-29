from blockcrypt_core.blockcrypt import *
from blockcrypt_core.shamir_backup import *
from blockcrypt_core.test_utils import *
from blockcrypt_core.blockcrypt_test import messages, passphrases, secrets, keys
from blockcrypt_core.qr_code import *
from blockcrypt_core.crypto import *

def test_basic_workflow():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    shamir_backup = ShamirBackup(3, 9)
    shamir_backup.load_data(encrypted_block.get_encrypted_data())
    backups = shamir_backup.backup()

    shamir_recover = ShamirBackup(3, 9)
    recovered_encrypted_block = shamir_recover.recover([backups[2], backups[4], backups[6]])
    encrypted_block = parse_compact_encrypted_block(recovered_encrypted_block)

    encrypted_block.set_kdf(insecure_kdf)
    decrypted_block = encrypted_block.decrypt(passphrases)

    assert block == decrypted_block

def test_qr_code_workflow():
    block = Block(secrets, insecure_kdf, 64, 1024, referenceSalt, referenceIv)
    encrypted_block = block.encrypt()
    shamir_backup = ShamirBackup(3, 9)
    shamir_backup.load_data(encrypted_block.get_encrypted_data())
    backups = shamir_backup.backup()

    for i, backup in enumerate(backups):
        generate_qr_code(backup, save_path=f"assets/qr_code_{i}.png")

    print("QR Code generated")
    shamir_recover = ShamirBackup(3, 9)

    selected_idx = [2, 4, 3]
    qr_codes_data = [read_qr_code(f"assets/qr_code_{i}.png") for i in selected_idx]

    assert qr_codes_data[0] == backups[2]
    recovered_encrypted_block = shamir_recover.recover(qr_codes_data)
    encrypted_block = parse_compact_encrypted_block(recovered_encrypted_block)

    encrypted_block.set_kdf(insecure_kdf)
    decrypted_block = encrypted_block.decrypt(passphrases)

    assert block == decrypted_block

def test_qr_code_workflow_secure_kdf():
    block = Block(secrets, secure_kdf, 64, 1024)
    encrypted_block = block.encrypt()
    
    shamir_backup = ShamirBackup(3, 9)
    shamir_backup.load_data(encrypted_block.get_encrypted_data())
    backups = shamir_backup.backup()

    for i, backup in enumerate(backups):
        generate_qr_code(backup, save_path=f"assets/qr_code_{i}.png")

    print("QR Code generated")
    shamir_recover = ShamirBackup(3, 9)

    selected_idx = [2, 4, 3]
    qr_codes_data = [read_qr_code(f"assets/qr_code_{i}.png") for i in selected_idx]

    assert qr_codes_data[0] == backups[2]
    recovered_encrypted_block = shamir_recover.recover(qr_codes_data)
    encrypted_block = parse_compact_encrypted_block(recovered_encrypted_block)
    encrypted_block.set_kdf(secure_kdf)
    decrypted_block = encrypted_block.decrypt(passphrases)

    assert block == decrypted_block



if __name__ == "__main__":
    test_basic_workflow()
    test_qr_code_workflow()
    test_qr_code_workflow_secure_kdf()