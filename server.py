#!/bin/bash sudo /home/eric/Envs/my-project/bin/python "$@"

"""
Name: Jasmin Maizel
Final Project subject: Cryptography - Enigma
this is the Server file - it deals with all the clients and connects them.
Python Version: 3.7.4
Date: 10.02.2021
"""

import socket
from pickle import dumps, loads
from threading import Thread

from rsa_class import RSA_encryption
from users import Users


class Server:
    """
    This is the server class. It handles clients and
    transfers messages among the clients.
    """

    def __init__(self, ip="0.0.0.0", port=2000):
        """
        this function creates the server and waits for clients
        """
        server_socket = socket.socket()  # creating the server
        server_socket.bind((ip, port))
        server_socket.listen(10)
        print("server is listening on IP", ip, "PORT", port)

        self.rsa_instance = RSA_encryption()  # RSA object for encrypting and decrypting messages

        # in order to keep track of the clients, we have the following variables:
        self.all_messages = []
        self.connected_users = []

        # this thread transfers all the available messages to the rest of the clients
        thread_msg = Thread(target=self.send_msg)
        thread_msg.daemon = True
        thread_msg.start()

        while True:
            try:
                # accepting a new client
                (client_socket, client_address) = server_socket.accept()
                # creating a new client thread
                client_thread = Thread(target=self.deal_with_client,
                                       args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()  # starting the thread
            except:
                pass

    def deal_with_client(self, client_soc, client_add):
        """
        this function deals with the client. it admits its logging in
        to the system and receives messages from the client.
        :param client_soc:
        :param client_add:
        :return:
        """
        print("new client has connected")

        # exchanging public keys
        client_soc.send(self.rsa_instance.get_public_key())
        client_key = client_soc.recv(8000)
        # required variables in order to know whether or not to continue running
        # the code and whether or not the client is connected and available for messages.
        finish = False
        is_connected = False

        # creating users object in order to submit the client to the system
        users_object = Users()
        user_name = ""
        while not is_connected and not finish:
            try:
                action = loads(client_soc.recv(1024))
                data = self.rsa_instance.decrypt(client_soc.recv(8000)).decode().split(";")
                if action == "log in":
                    response = users_object.log_in(data[0], data[1], data[2], data[3])
                    for i in self.connected_users:
                        if data[0] in i:
                            response = "user already connected with another device."
                    if response == "access granted":
                        user_name = data[0]
                        self.connected_users.append([user_name, client_soc, client_add, client_key])
                        is_connected = True
                else:
                    response = users_object.sign_in(data[0], data[1], data[2],
                                                    data[3], data[4], data[5])

                client_soc.send(self.rsa_instance.encrypt(response.encode(), client_key))

            except EOFError:
                # the EOFError means the client has disconnected before logging in
                # there is no need for the second loop, so:
                finish = True
                print("client has disconnected")
            except ConnectionResetError:
                # the ConnectionResetError means the client has disconnected before logging in
                # there is no need for the second loop, so:
                finish = True
                print("client has disconnected")

        while not finish:
            try:
                chunks = []
                bytes_recd = 0
                msg_length = loads(client_soc.recv(8000))
                while bytes_recd < msg_length:
                    chunk = client_soc.recv(min(msg_length - bytes_recd, 2048))
                    if chunk == b'':
                        raise RuntimeError("socket connection broken")
                    chunks.append(chunk)
                    bytes_recd = bytes_recd + len(chunk)
                approve_str = client_soc.recv(16).decode()
                print(approve_str)
                encryption_data = self.rsa_instance.decrypt(client_soc.recv(8000))
                self.all_messages.append([b''.join(chunks), encryption_data, user_name])
            except ConnectionResetError:
                # this ConnectionResetError means the client has disconnected,
                # therefore, we will remove it from the client list and finish the process
                for i in self.connected_users:
                    if user_name in i:
                        self.connected_users.remove(i)

                finish = True
                print("client has disconnected")

    def send_msg(self):
        """
        this function sends all the connected users the incoming messages
        the chatting logic:
        When sending a message, the client will encrypt his message
        with the server's public key.
        The server will decrypt it and re-encrypt it with the public key of
        every single client connected and send it to them.
        :return:
        """
        while True:
            for msg, encryption_data, sender_username in self.all_messages:
                for user_name, client_sock, client_add, public_key in self.connected_users:
                    if user_name != sender_username:
                        total_sent = 0
                        new_msg = msg + (";"+sender_username).encode()
                        msg_length = len(new_msg)
                        client_sock.send(dumps(msg_length))
                        while total_sent < msg_length:
                            sent = client_sock.send(new_msg[total_sent:])
                            if sent == 0:
                                raise RuntimeError("socket connection broken")
                            total_sent = total_sent + sent
                        encrypted_data_key = self.rsa_instance.encrypt(encryption_data, public_key)
                        client_sock.send(dumps(encrypted_data_key))
                self.all_messages.remove([msg, encryption_data, sender_username])


if __name__ == '__main__':
    server_instance = Server()
