from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename, password=None):
    key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(filename, 'wb') as key_file:
        key_file.write(key_data)


def save_public_key(public_key, filename):
    key_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as key_file:
        key_file.write(key_data)


def load_private_key(filename, password=None):
    with open(filename, 'rb') as key_file:
        key_data = key_file.read()
    private_key = serialization.load_pem_private_key(
        key_data,
        password=password
    )
    return private_key


def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        key_data = key_file.read()
    public_key = serialization.load_pem_public_key(key_data)
    return public_key


def load_public_key_bytes(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes
