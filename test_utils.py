from blockcrypt import *
import hmac
import hashlib

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


referenceSalt = base64.b64decode("Com4/aFtBjaGdvbjgi5UNw==")
referenceIv = base64.b64decode("u05uhhQe3NDtCf39rsxnig==")
referenceHeadersSignature = base64.b64decode("UJO8m9woe0CrEkyHqOuLN9AN9x7wkTOprSYeFHMaMm29z6l7CmeXeO7IlcUorqytXy2zChcJdDN0z6ulBCXs+g==")



def insecure_kdf(passphrase, salt):
    hmac_sha256 = hmac.new(salt, passphrase, hashlib.sha256)
    digest = hmac_sha256.digest()

    return digest


keys = [passphrase.derive_key(insecure_kdf, referenceSalt) for passphrase in passphrases]
