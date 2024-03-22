from core.shamir_backup import *

def test_shamir_backup_basic():
    shamir_backup = ShamirBackup(5, 9)
    data = b'this is the secret message'
    shamir_backup.load_data(data)
    backups = shamir_backup.backup()

    shamir_recover = ShamirBackup(5, 9)
    data_recovered = shamir_recover.recover(backups[1:6])
    assert data == data_recovered

if __name__ == "__main__":
    test_shamir_backup_basic()
    