from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import socket
import rsa_keys as rsa


def calculate_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()


def generate_signature(private_key, data):
    print('hash is generating for elf file')
    hash_value = calculate_hash(data)
    signature = private_key.sign(
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def encrypt_rsa(public_key, data):
    encrypted_data = public_key.encrypt(
        data,
        padding.PKCS1v15()
    )
    return encrypted_data


# Send the encrypted data and signature to the client
def server_process(elf_path, password=b'hmobis'):
    print('decryption should be done but skipping for now')
    # Generate RSA key pair
    print('generating and saving rsa keys')
    sign_key, verify_key = rsa.generate_rsa_key_pair()
    rsa.save_private_key(sign_key, 'keys\\private_key.pem', password=password)
    rsa.save_public_key(verify_key, 'keys\\public_key.pem')
    print('loading rsa keys')
    loaded_private_key = rsa.load_private_key('keys\\private_key.pem', password=password)
    loaded_public_key = rsa.load_public_key('keys\\public_key.pem')
    print('reading elf file')
    with open(elf_path, 'rb') as file:
        elf_data = file.read()
    print('generating elf ds')
    signature = generate_signature(loaded_private_key, elf_data)
    print('encrypting elf data with server rsa key')
    encrypted_data = encrypt_rsa(loaded_public_key, elf_data)
    return encrypted_data, signature, loaded_public_key


def server_program(host, port, encrypted_elf, signature, vk, upflag=False):
    vk_bytes = rsa.load_public_key_bytes(vk)
    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))

    update = 'update info please'
    unavl = 'no update, you are at the latest version'
    avl = 'update available'
    elf = 'send ota package'
    sign = 'send Signature'
    vkey = 'send verifying key'
    rcvd = 'Received'
    disconn = 'start installing & disconnect'
    rpl = 'please respond'
    end = 'thank you end'

    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024).decode()
        print("from connected user: " + str(data))
        if data == update and not upflag:
            conn.send(unavl.encode())
        elif data == update and upflag:
            conn.send(avl.encode())
        elif data == elf:
            conn.send(encrypted_elf)
        elif data == sign:
            conn.send(signature)
        elif data == vkey:
            conn.sendall(vk_bytes)
        elif data == rcvd or data == end:
            conn.send(disconn.encode())
            conn.close()  # close the connection
            break
        else:
            conn.send(rpl.encode())
            break
    return


if __name__ == '__main__':
    hostname = '127.0.0.1'
    port = 3000
    elf_path = 'input_test.sre' # give sre path here
    elf_data, digital_sign, verifying_key = server_process(elf_path)
    print('server process completed')
    server_program(hostname, port, elf_data, digital_sign, verifying_key, True)
    print('Connection closed, Thank you')
