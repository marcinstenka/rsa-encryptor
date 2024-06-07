import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537
initial_vector = 1234
INITIAL_VECTOR_BYTES = initial_vector.to_bytes(16, 'big')

def generate_rsa_key_pair(pin):
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    aes_key = int(pin).to_bytes(32, 'big')
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(INITIAL_VECTOR_BYTES), backend=default_backend())
    encryptor = cipher.encryptor()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_private_key = encryptor.update(private_key_bytes) + encryptor.finalize()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_private_key, public_key_pem, aes_key
def save_keys_to_files(encrypted_private_key, public_key):
    with open('private_key.pem', 'wb') as f:
        pem_header = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        pem_footer = b"-----END ENCRYPTED PRIVATE KEY-----\n"
        base64_data = base64.encodebytes(encrypted_private_key)
        pem_encoded_data = pem_header + base64_data + pem_footer
        f.write(pem_encoded_data)

    with open('public_key.pem', 'wb') as f:
        f.write(public_key)


def decrypt_private_key(encrypted_private_key, pin):
    aes_key = int(pin).to_bytes(32, 'big')
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(INITIAL_VECTOR_BYTES), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_private_key_bytes = decryptor.update(encrypted_private_key) + decryptor.finalize()

    private_key = serialization.load_pem_private_key(
        decrypted_private_key_bytes,
        password=None,
        backend=default_backend()
    )

    return private_key


def load_and_decrypt_private_key(filename, pin):
    with open(filename, 'rb') as f:
        encrypted_private_key_pem = f.read()
        # Extract the base64 encoded part
        encrypted_private_key_base64 = b''.join(encrypted_private_key_pem.split(b'\n')[1:-1])
        encrypted_private_key = base64.decodebytes(encrypted_private_key_base64)
        return decrypt_private_key(encrypted_private_key, pin)


def generate(pin):

    encrypted_private_key, public_key, aes_key = generate_rsa_key_pair(pin)

    save_keys_to_files(encrypted_private_key, public_key)