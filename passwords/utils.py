import json
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_master_key(master_password: str, vault) -> bytes:
    params = json.loads(vault.kdf_params.decode())

    salt = bytes.fromhex(params["salt"])  
    iterations = params["iterations"]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    return kdf.derive(master_password.encode())


def derive_vault_key(master_password: str, vault) -> bytes:

    master_key = derive_master_key(master_password,vault)

    data = vault.vault_key_encrypted
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]

    cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
    vault_key = cipher.decrypt_and_verify(ciphertext, tag)

    return vault_key