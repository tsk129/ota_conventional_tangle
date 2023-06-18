from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import socket
import rsa_keys as rsa


def calculate_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()


def verify_signature(public_key, data, signature):
    hash_value = calculate_hash(data)
    try:
        public_key.verify(
            signature,
            hash_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def decrypt_rsa(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.PKCS1v15()
    )
    return decrypted_data


def client_program(host, port):
    # as both code is running on same pc
    # socket server port number
    server_data = []
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    update = 'update info please'
    unavl = 'no update, you are at the latest version'
    avl = 'update available'
    elf = 'send ota package'
    sign = 'send Signature'
    vkey = 'send verifying key'
    rcvd = 'Received'
    disconn = 'start installing & disconnect'
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
            server_data.append(client_socket.recv(1024))  # change to elf file size
            print('received elf data')
            client_socket.send(sign.encode())
            server_data.append(client_socket.recv(1024))
            print('received signature')
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
    encrypted_data, signature, vk_bytes = server_list[0], server_list[1], server_list[2]
    vk = serialization.load_pem_public_key(vk_bytes)
    sk = rsa.load_private_key('keys\\private_key.pem', password=b'hmobis')
    print('decrypting data')
    decrypted_data = decrypt_rsa(sk, encrypted_data)
    print('verifying signature')
    signature_valid = verify_signature(vk, decrypted_data, signature)
    print('signature verification: ', signature_valid)
    if signature_valid:
        # Signature is valid, proceed with the decrypted data (ELF file)
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
