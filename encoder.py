import secrets, hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

#TODO comments
def generate_random_16byte(): #Generate random (using secrets) 16 byte value
    return secrets.token_bytes(16)

def generate_key(password, salt):
    """
    :param password: User given password
    :param salt: Salt generated in generate_salt() used to add randomly generated data for added security
    :return: Using PBKDF2-HMAC key derivation funtion (Kdf) with SHA-256 a key is derived from password and salt
    """
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=salt, iterations=100000, length=32)
    key = kdf.derive(password.encode('utf-8'))
    return key

def hash_data(data, salt):
    data_bytes = data.encode('utf-8')
    data_with_salt = data_bytes + salt
    print(salt)
    print(data)
    hashed_data = hashlib.sha256(data_with_salt).hexdigest()
    return hashed_data

def encrypt_data(data, key, iv):
    #print("Data before encryption", data)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    data = data.encode('utf-8')
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    #print("Encrypted data", encrypted_data)
    return encrypted_data

def decrypt_data(encrypted_data, key, iv):
    #print("Encrypted data before decryption", encrypted_data)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def main():
    password = input("Password:")
    data_to_encrypt = input("Data:")
    salt = generate_random_16byte()
    key = generate_key(password, salt)
    iv = generate_random_16byte()

    hashed_data = hash_data(data_to_encrypt, salt)
    print("hashed data", hashed_data)
    encrypted_data = encrypt_data(hashed_data, key, iv)
    print("encrypted data", encrypted_data)

    #print("Encryption was successful.")

    decrypted_data = decrypt_data(encrypted_data, key, iv).decode('utf-8')
    #print("Decryption was successfull.")
    print("decrypted data", decrypted_data)

    if hashed_data == hash_data(password, salt):
        print("Success")
"""
    if decrypted_data == hashed_data:
        print("Data integrity verified.")
    else:
        print("Data integrity compromised.")
"""

if __name__ == "__main__":
    main()
