"""
Name: Jasmin Maizel
Final Project subject: Cryptography - Enigma
this is the Users file, accesses the database
Python Version: 3.7.4
Date: 10.02.2021
"""

import functools
import hashlib
import re
import sqlite3


class Users:
    """
    class database of users. it checks the log in, sign in and create users.
    """

    def __init__(self):
        """
        connects to the users database
        """
        self.conn = sqlite3.connect("UsersDatabase.db")
        self.cur = self.conn.cursor()

    def log_in(self, user_name, password, passcode, time):
        """
        checks whether client can log in to the system, if his user exists.
        :param user_name:
        :param password:
        :param passcode:
        :param time:
        :return: a message that contains the information whether or not the log in is permitted.
        """
        if user_name == "" or password == "" or passcode == "":
            return "all fields must be filled"
        try:
            if int(passcode) != int(time) * 2 + 5:
                return "passcode incorrect"
        except ValueError:
            return "passcode incorrect"
        row_user_name = list(self.cur.execute('SELECT * FROM users WHERE username=?',
                                            (hashlib.md5(user_name.encode()).hexdigest(),)))
        if row_user_name != [] and row_user_name[0][2] == \
                hashlib.md5(password.encode()).hexdigest():
            return "access granted"
        return "user name or password incorrect"

    def sign_in(self, user_name, user_id, password1, password2, passcode, time):
        """
        checks if the user can be created and that it does not already exist.
        :param user_name:
        :param user_id:
        :param password1:
        :param password2:
        :param passcode:
        :param time:
        :return: a message that contains the information whether or not the sign in is permitted.
        """
        if user_name == "" or user_id == "" or password1 == "" or password2 == "" or passcode == "":
            return "all fields must be filled"
        try:
            if int(passcode) != int(time) ** 2:
                return "passcode incorrect"
        except ValueError:
            return "passcode incorrect"

        id_response = self.__is_id_standard__(user_id)
        if id_response != "ID is valid":
            return id_response
        if password1 != password2:
            return "passwords do not match"
        if self.__is_username_standard__(user_name) != "username approved":
            return self.__is_username_standard__(user_name)
        if self.__is_password_standard__(password1) != "password approved":
            return self.__is_password_standard__(password1)
        self.cur.execute("INSERT INTO users (username, ID, password) \
              VALUES (?, ?, ?)", [hashlib.md5(user_name.encode()).hexdigest(),
                                  hashlib.md5(user_id.encode()).hexdigest(),
                                  hashlib.md5(password1.encode()).hexdigest()])
        self.conn.commit()
        return "user successfully signed in. to complete the process, log in."

    def __is_username_standard__(self, user_name):
        """
        checks if the user name is ok
        :param user_name:
        :return: a message that contains the information whether or
        not the username is permitted for use.
        """
        row_user_name = list(self.cur.execute('SELECT * FROM users WHERE username=?',
                                            (hashlib.md5(user_name.encode()).hexdigest(),)))
        if row_user_name:
            return "user name is taken"
        for i in user_name:
            if not i.isalpha() and not i.isnumeric():
                return "user name can only contain numbers and english letters"
        return "username approved"

    def __is_id_standard__(self, user_id):
        """
        checks if the ID is valid.
        ID must contain 9 digits.
        :param user_id:
        :return:  a message that contains the information whether or
        not the ID is permitted for use.
        """
        row_id = list(self.cur.execute('SELECT * FROM users WHERE ID=?',
                                       (hashlib.md5(user_id.encode()).hexdigest(),)))
        if row_id:
            return "user ID already exists in system"
        if len(user_id) < 9:
            return "ID must contain 9 digits"
        try:
            id_verification = []
            for i in range(len(user_id)):
                if i % 2 == 0:
                    id_verification.append(int(user_id[i]))
                else:
                    id_verification.append(int(user_id[i]) * 2)
            for i in range(len(id_verification)):
                id_verification[i] = id_verification[i] % 10 + id_verification[i] // 10
            id_verification_sum = functools.reduce(lambda x, y: x + y, id_verification)
            if id_verification_sum % 10 == 0:
                return "ID is valid"
            return "ID invalid"

        except:
            return "ID must contain 9 digits"

    @staticmethod
    def __is_password_standard__(password):
        """
        checks if the password is valid.
        its length must be at least 8 characters, contain at least one
        of each: symbol, small and big letter.
        :param password:
        :return: a message that contains the information whether or
        not the password is permitted for use.
        """
        # calculating the length of the password
        if len(password) < 8:
            return "password must contain at least 8 characters"

        # searching for digits
        if re.search(r"\d", password) is None:
            return "password must contain at least one digit"

        # searching for uppercase
        if re.search(r"[A-Z]", password) is None:
            return "password must contain at least one uppercase letter"

        # searching for lowercase
        if re.search(r"[a-z]", password) is None:
            return "password must contain at least one lowercase letter"

        # searching for symbols
        if re.search(r"[ !#$%&?@'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None:
            return "password must contain at least one symbol"

        return "password approved"
