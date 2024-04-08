from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

KEY_SIZE = 4096
initial_vector = 1234
INITIAL_VECTOR_BYTES = initial_vector.to_bytes(16, 'big')

def generate_rsa_key_pair(pin):
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used value for RSA
        key_size=KEY_SIZE,  # Key size (in bits)
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Serialize the private key to PEM format with AES encryption
    aes_key = pin.to_bytes(32, 'big')
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(INITIAL_VECTOR_BYTES), backend=default_backend())
    encryptor = cipher.encryptor()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_private_key = encryptor.update(private_key_bytes) + encryptor.finalize()

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_private_key, public_key_pem, aes_key


# Generate RSA key pair
encrypted_private_key, public_key, aes_key  = generate_rsa_key_pair(1234)

# Print the encrypted private key in PEM format
def print_encrypted_private_key_pem(encrypted_private_key):
    pem_header = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    pem_footer = b"-----END ENCRYPTED PRIVATE KEY-----\n"
    base64_data = base64.encodebytes(encrypted_private_key)
    pem_encoded_data = pem_header + base64_data + pem_footer
    print(pem_encoded_data.decode('utf-8'))

# Call the function to print the encrypted private key in PEM format



# Print the encrypted private key, public key, AES key, and AES IV
print("Encrypted Private Key:")
print_encrypted_private_key_pem(encrypted_private_key)
print("\nPublic Key:")
print(public_key.decode('utf-8'))
print("\nAES Key:")
print(aes_key.hex())
