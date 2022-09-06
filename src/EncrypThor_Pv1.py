import os
import shutil

from EncrypThor import EncrypThor


def encryption_protocol_v1(path, keyword, key):
    """Encryption protocol V1 (one key only)

    Args:
        path (str): path of your file
        keyword (str): A random keyword
        key (str): Your key
    """

    # Init EncrypThor 2
    encrypthor = EncrypThor()

    # Generate two keys from one key
    key_1 = encrypthor.keys_gen(password=keyword, salt=key)

    # Encrypt the data
    encrypthor.encrypt_data(key=key_1, path_in=f"{path}")

    # Cut the encrypted in blocks of random size + remove the .enc file
    encrypthor.cutin_blocks(path_in=f"{path}.enc", path_out=f"{path}.encx")
    os.remove(f"{path}.enc")

    # Will coming in next updates
    #encrypthor.shuffle_blocks(path_in=f"{path}.encx")

    # Remove the clear file
    os.remove(path)


def decryption_protocol_v1(path, keyword, key):
    """Decryption protocol V1

    Args:
        path (str): path of your file
        keyword (str): A random keyword
        key (str): Your key
    """

    # Init EncrypThor 2
    encrypthor = EncrypThor()

    # Generate the key
    key_1 = encrypthor.keys_gen(password=keyword, salt=key)

    # Will coming in next updates
    #encrypthor.sort_blocks(path_in=f"{path}")

    # Join the .encx folder
    encrypthor.joinin_blocks(path_in=f"{path}", path_out=f"{path[:-1]}")

    # Decrypt the file
    encrypthor.decrypt_data(key=key_1, path_in=f"{path[:-1]}")

    # Remove the .encx folder and the encrypted file
    os.remove(f"{path[:-1]}")
    shutil.rmtree(path)
