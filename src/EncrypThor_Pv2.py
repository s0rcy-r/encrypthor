import os
import shutil

from EncrypThor import EncrypThor


def encryption_protocol_v2(path, key, keyword):
    """Encryption protocol V2 (two keys)

    Args:
        path (str): path of your file
        keyword (str): A random keyword
        key (str): Your key
    """

    # Init EncrypThor 2
    encrypthor = EncrypThor()
    
    # Generate two keys from one key
    key_1 = encrypthor.keys_gen(password=keyword, salt=key)
    key_2 = encrypthor.keys_gen(password=keyword, salt=key_1)

    # Encrypt the data
    encrypthor.encrypt_data(key=key_1, path_in=f"{path}")

    # Cut the encrypted in blocks of random size + remove the .enc file
    encrypthor.cutin_blocks(path_in=f"{path}.enc", path_out=f"{path}.encx")
    os.remove(f"{path}.enc")

    # Will coming in next updates
    #encrypthor.shuffle_blocks(path_in=f"{path}.encx")

    # List the files in the .encx folder
    dir = os.listdir(f"{path}.encx")

    # Decrypt each files in the .encx folder
    for i in dir:
        encrypthor.encrypt_data(key=key_2, path_in=f"{path}.encx/{i}")
        os.remove(f"{path}.encx/{i}")

    # Remove the clear file
    os.remove(path)


def decryption_protocol_v2(path, key, keyword):
    """Decryption protocol V2

    Args:
        path (str): path of your file
        keyword (str): A random keyword
        key (str): Your key
    """ 

    # Init EncrypThor 2
    encrypthor = EncrypThor()

    # Generate two keys from one key
    key_1 = encrypthor.keys_gen(password=keyword, salt=key)
    key_2 = encrypthor.keys_gen(password=keyword, salt=key_1)

    # Will coming in next updates
    #encrypthor.sort_blocks(path_in=f"{path}")

    # List the files in the .encx folder
    dir_2 = os.listdir(f"{path}")

    # Decrypt each files in the .encx folder
    for j in dir_2:
        encrypthor.decrypt_data(key=key_2, path_in=f"{path}/{j}")
        os.remove(f"{path}/{j}")

    # Join the .encx folder
    encrypthor.joinin_blocks(path_in=f"{path}", path_out=f"{path[:-1]}")

    # Decrypt the encrypted file
    encrypthor.decrypt_data(key=key_1, path_in=f"{path[:-1]}")

    # Remove the .encx folder and the encrypted file
    os.remove(f"{path[:-1]}")
    shutil.rmtree(path)
