import hmac
import hashlib
import base64


referenceSalt = base64.b64decode("Com4/aFtBjaGdvbjgi5UNw==")
referenceIv = base64.b64decode("u05uhhQe3NDtCf39rsxnig==")
referenceHeadersSignature = base64.b64decode("UJO8m9woe0CrEkyHqOuLN9AN9x7wkTOprSYeFHMaMm29z6l7CmeXeO7IlcUorqytXy2zChcJdDN0z6ulBCXs+g==")


def insecure_kdf(passphrase, salt):
    hmac_sha256 = hmac.new(salt, passphrase, hashlib.sha256)
    digest = hmac_sha256.digest()

    return digest


