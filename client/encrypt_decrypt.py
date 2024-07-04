from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

# Load RSA keys
with open("../keys/public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

with open("../keys/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

def encrypt_file(file_path):
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        file_data = f.read()

    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(f"{file_path}.enc", "wb") as f:
        f.write(iv + encrypted_aes_key + encrypted_data)

def decrypt_file(encrypted_file_path):
    with open(encrypted_file_path, "rb") as f:
        iv = f.read(16)
        encrypted_aes_key = f.read(256)  # RSA key size in bytes
        encrypted_data = f.read()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    with open(f"{encrypted_file_path}.dec", "wb") as f:
        f.write(decrypted_data)

# Example usage
# encrypt_file("example.txt")
# decrypt_file("example.txt.enc")
