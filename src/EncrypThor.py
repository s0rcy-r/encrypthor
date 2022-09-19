import os
import secrets
import string
import struct
import random

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


class EncrypThor:
    def __init__(self, keyword="encrypthor2", loop=10, key_lenght=32):
        """Constructor of the class

        Args:
            keyword (str, optional): Keyword used for the keys generation. Defaults to "encrypthor2".
            loop (int, optional): Number of loop for generating the key. Defaults to 10.
            key_lenght (int, optional): Key length. Defaults to 32.
        """

        # Generate a salt for the keys generator
        self.SALT = self.salt_gen(keyword, loop, key_lenght)
        self.key_lenght = key_lenght

    def encrypt_data(self, key, path_in, chunk_size=64 * 1024):
        """Function to encrypt a file

        Args:
            key (str): Your key
            path_in (str): path of the file
            chunk_size (int, optional): Size of chunks. Defaults to 64*1024.
        """

        output_filename = path_in + '.enc'
        iv = os.urandom(16)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(path_in)
        with open(path_in, 'rb') as inputfile:
            with open(output_filename, 'wb') as outputfile:
                outputfile.write(struct.pack('<Q', filesize))
                outputfile.write(iv)
                while True:
                    chunk = inputfile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    outputfile.write(encryptor.encrypt(chunk))

    def decrypt_data(self, key, path_in, chunk_size=24 * 1024):
        """Function to decrypt a file

        Args:
            key (str): Your key
            path_in (str): path of the file
            chunk_size (int, optional): Size of chunks. Defaults to 24*1024.
        """

        output_filename = os.path.splitext(path_in)[0]
        output_filename = output_filename
        with open(path_in, 'rb') as infile:
            origsize = struct.unpack(
                '<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            with open(output_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))
                outfile.truncate(origsize)

    def cutin_blocks(self, path_in, path_out):
        """Function to cut a file in multiple blocks of random size

        Args:
            path_in (str): Path of your file
            path_out (str): Folder where you want to have your file cut
        """
        if not os.path.exists(path_out):
            os.makedirs(path_out)

        partnum = 0
        input = open(path_in, 'rb')
        while 1:
            chunk = input.read(int(random.uniform(0.01, 1.4) * 1024*1000))
            if not chunk:
                break
            partnum = partnum + 1
            filename = os.path.join(path_out, ('%0d' % partnum))
            fileobj = open(filename, 'wb')
            fileobj.write(chunk)
            fileobj.close()
        input.close()
        #assert partnum <= 9999
        return partnum

    def joinin_blocks(self, path_in, path_out):
        """Function to join file block into one file

        Args:
            path_in (str): Path where the blocks are
            path_out (str): Path where you want your file
        """

        readsize = 1024

        output = open(path_out, 'wb')
        parts = [str(i) for i in range(1, len(os.listdir(path_in))+1)]

        for filename in parts:
            filepath = os.path.join(path_in, filename)
            fileobj = open(filepath, 'rb')
            while 1:
                filebytes = fileobj.read(readsize)
                if not filebytes:
                    break
                output.write(filebytes)
            fileobj.close()
        output.close()

    def shuffle_blocks(self, path_in):
        """Function to shuffle the blocks

        Args:
            path_in (str): Path where your blocks are
        """

        # List the blocks in the .encx dir
        dir = os.listdir(path_in)

        # Get the alphabet + digits
        alphabet = string.ascii_letters + string.digits

        # Rename each files
        for i in dir:
            os.rename(
                src=f"{path_in}/{i}", dst=f"{path_in}/{''.join(random.choice(alphabet) for i in range(random.randrange(10,22)))}-{i}a7m.{secrets.token_urlsafe(16)}")

    def sort_blocks(self, path_in):
        """Function so sort randomized blocks

        Args:
            path_in (str): Path where your blocks are
        """

        # List the blocks in the .encx dir
        dir = os.listdir(path_in)

        # Rename each files by her positions (1 to ...)
        for i in dir:
            idx_1 = i.find("-")
            idx_2 = i.find("a7m.")
            os.rename(src=f"{path_in}/{i}",
                      dst=f"{path_in}/{i[idx_1+1:idx_2]}")

    def keys_gen(self, password, salt=""):
        """Keys generator

        Args:
            password (str): Your key in string
            salt (str, optional): The salt. Defaults to "".

        Returns:
            str: your key as bytes
        """

        # Check the salt
        if salt == "":
            # Generate the key
            key = PBKDF2(password, self.SALT, dkLen=self.key_lenght)
        else:
            # Generate the key
            key = PBKDF2(password, salt, dkLen=self.key_lenght)

        # Return the key
        return key

    def salt_gen(self, keyword, loop, key_lenght):
        """Salt generator

        Args:
            keyword (str): Keyword to generate the salt
            loop (int): Number of loops
            key_lenght (int): Length of the key

        Returns:
            str: The salt
        """

        # Init the salt generator with a common salt
        salt_init = b'\x18\x04\xa8\x92\xdf\\~\x9c\xf5\x85\xf3^n\r\x89\x1a\xdd\xe85\x11\xab\xe1ouTc\xec\x06\xdc\x8fj\xed'
        salt = PBKDF2(keyword, salt_init, dkLen=key_lenght)

        # Loop to randomize the salt generation
        for i in range(loop):
            salt = PBKDF2(str(secrets.randbits(len(keyword)))+keyword +
                          str(secrets.randbits(key_lenght*loop)), salt, dkLen=key_lenght)

        # Return the salt
        return salt
