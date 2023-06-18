import base64
import hashlib
import socket

import iota
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import rsa_keys as rsa


def calculate_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()


def encrypt_rsa(public_key, data):
    encrypted_data = public_key.encrypt(
        data,
        padding.PKCS1v15()
    )
    return encrypted_data


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


def calculate_previous_hashes(data):
    sha256_hash = hashlib.sha256(data).hexdigest()
    md5_hash = hashlib.md5(data).hexdigest()
    return sha256_hash, md5_hash


def send_to_tangle(data, sha256_hash, md5_hash):
    # Initialize IOTA API instance
    api = iota.Iota("https://nodes.devnet.iota.org:443")
    # Create a new transaction object
    tx = iota.ProposedTransaction(
        address=iota.Address("RECEIVER_ADDRESS"),
        message=iota.TryteString.from_string(base64.b64encode(data).decode()),
        tag=iota.Tag("SERVER"),
        value=0
    )

    # Attach the previous hashes as tags to the transaction
    tx.tag = iota.Tag(sha256_hash + md5_hash)

    # Send the transaction to the Tangle
    response = api.send_transfer([tx])

    # Return the transaction hash
    return response["bundle"][0].hash


def server_process(elf_path, password=b'hmobis'):
    print('decryption should be done but skipping for now')
    # Generate ecdsa key pair
    print('generating and saving ecdsa keys')
    print('generating and saving rsa keys')
    sign_key, verify_key = rsa.generate_rsa_key_pair()
    rsa.save_private_key(sign_key, 'keys\\private_key_tang.pem', password=password)
    rsa.save_public_key(verify_key, 'keys\\public_key_tang.pem')
    print('loading rsa keys')
    loaded_sign_key = rsa.load_private_key('keys\\private_key_tang.pem', password=password)
    loaded_verify_key = rsa.load_public_key('keys\\public_key_tang.pem')
    print('reading ota file')
    with open(elf_path, 'rb') as file:
        ota_data = file.read()
    print('encrypting elf file')
    encrypted_file = encrypt_rsa(loaded_verify_key, ota_data)
    print('Signing the encrypted file')
    signature = generate_signature(loaded_sign_key, encrypted_file)
    print('forming signed file')
    signed_file = signature + encrypted_file
    print('signature length is : ', len(signature))
    # Calculate previous hashes for encrypted file
    sha256_hash, md5_hash = calculate_previous_hashes(signed_file)
    print('Send the signed file and previous hashes to the Tangle')
    tx_hash = send_to_tangle(signed_file, sha256_hash, md5_hash)
    print("Transaction Hash: " + str(tx_hash))
    return tx_hash, signed_file, loaded_verify_key


def server_program(host, port, tx_hash, signed_data, vk, upflag=False):
    vk_bytes = rsa.load_public_key_bytes(vk)
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))

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

    while True:
        data = conn.recv(1024).decode()
        print("from connected user: " + str(data))
        if data == update and not upflag:
            conn.send(unavl.encode())
        elif data == update and upflag:
            conn.send(avl.encode())
        elif data == elf:
            conn.send(tx_hash)
        elif data == sign:
            conn.send(signed_data)
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
    elf_path = 'C:\\Users\\Sampath\\PycharmProjects\\otamobis\\inputtest.sre'
    tangle_hash, signed_data, verifying_key = server_process(elf_path)
    print('server process completed')
    print(tangle_hash, signed_data, verifying_key)
    # server_program(hostname, port, tangle_hash, signed_data, verifying_key, True)
    print('Connection closed, Thank you')
