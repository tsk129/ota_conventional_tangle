import socket
import iota
import iota_client


def server_program(host, port):
    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together
    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    data = conn.recv(1024)
    server_socket.close()
    return data


if __name__ == '__main__':
    hostname = '127.0.0.1'
    port = 5000
    # data = server_program(hostname, port)
    # print(data)

    # create a client with a node
    client = iota_client.Client(
        nodes_name_password=[['https://api.lb-0.h.chrysalis-devnet.iota.cafe']])

    print(client.get_info())
