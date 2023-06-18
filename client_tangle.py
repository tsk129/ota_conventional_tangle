import socket
import hashlib
import iota
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ecdsa import VerifyingKey, NIST384p


def unpad(s):
    padding_length = s[-1]
    return s[:-padding_length]


def decrypt_file(encrypted, key):
    iv = encrypted[:algorithms.AES.block_size // 8]
    ciphertext = encrypted[algorithms.AES.block_size // 8:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(decrypted)


def verify_previous_hashes(data, tags):
    calculated_sha256_hash = hashlib.sha256(data).hexdigest()
    calculated_md5_hash = hashlib.md5(data).hexdigest()
    if calculated_sha256_hash in tags and calculated_md5_hash in tags:
        return True
    else:
        return False


def verify_signature(data, signature, public_key):
    vk = VerifyingKey.from_string(public_key, curve=NIST384p)
    return vk.verify(signature, data)


def retrieve_from_tangle(tx_hash):
    print('Initializing IOTA API instance')
    api = iota.Iota("https://nodes.devnet.iota.org:443")
    print('Retrieving the transaction data from the Tangle')
    tx_data = api.get_transaction_data(tx_hash)
    print('Extracting the message from the transaction')
    message = tx_data['signatureMessageFragment']
    print('extracting tags')
    response = api.get_latest_inclusion([tx_hash])
    transaction = response['states'][tx_hash]
    tags = transaction['tags']
    return message.decode(), tags


def client_program(host, port):
    server_data = []
    client_socket = socket.socket()
    client_socket.connect((host, port))

    update = 'update info please'
    unavl = 'no update, you are at the latest version'
    avl = 'update available'
    elf = 'send tangle transaction hash'
    sign = 'send signed data'
    vkey = 'send verifying key'
    rcvd = 'Received'
    disconn = 'start installing & disconnect'
    rpl = 'please respond'
    end = 'thank you end'

    client_socket.send(update.encode())  # send message

    while True:
        data = client_socket.recv(1024).decode()  # receive response
        print('Received from server: ' + data)  # show in terminal
        if data == unavl:
            client_socket.send(end.encode())
            print('no update closing')
            client_socket.close()
            break
        elif data == avl:
            client_socket.send(elf.encode())
            server_data.append(client_socket.recv(1024))  # change to hash size
            print('received tangle hash')
            client_socket.send(sign.encode())
            server_data.append(client_socket.recv(1024))  # change to signed data size
            print('received signed data')
            client_socket.send(vkey.encode())
            server_data.append(client_socket.recv(1024))
            print('received vkey')
            if len(server_data) == 3:
                client_socket.send(rcvd.encode())
        elif data == disconn:
            print(rcvd + ' connection is closing')
            client_socket.close()  # close the connection
            break
    return server_data


def client_process(server_list):
    print('extracting data')
    tx_hash, signed_data, vk_bytes = server_list[0], server_list[1], server_list[2]
    print('extracting tags and signed data')
    message, tags = retrieve_from_tangle(tx_hash)
    signature = message[:256]
    encrypted_data = message[256:]
    vk = serialization.load_pem_public_key(vk_bytes)
    print('verifying previous two hashes for signed data')
    two_hash_valid = verify_previous_hashes(message, tags)
    print('verifying signature for encrypted data')
    signature_valid = verify_signature(encrypted_data, signature, vk)
    if signature_valid and two_hash_valid:
        # Signature is valid, proceed with the decrypted data (ELF file)
        print('decrypting data')
        decrypted_data = decrypt_file(encrypted_data, vk)
        print('verified and decrypted, proceed with installation')
        return decrypted_data
    else:
        print('verification failed, security breached, Please dont install')
        return False


if __name__ == '__main__':
    hostname = '127.0.0.1'
    port = 3000
    server_data = client_program(hostname, port)
    print(server_data)
    response = client_process(server_data)
    print(response)
