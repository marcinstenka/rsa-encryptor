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

    aes_key = pin.to_bytes(32, 'big')
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


def main(pin):
    encrypted_private_key, public_key, aes_key = generate_rsa_key_pair(pin)

    save_keys_to_files(encrypted_private_key, public_key)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python rsa-generate.py <PIN>")
        sys.exit(1)

    pin = int(sys.argv[1])

    main(pin)