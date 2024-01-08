import os, secrets, hashlib, base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#TODO comments
def generate_salt():
    return secrets.token_bytes(16)

def generate_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=salt, iterations=100000, length=32)
    key = kdf.derive(password.encode('utf-8'))
    return key

def hash_data(data, salt):
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise ValueError("Unsupported data type")

    data_with_salt = data_bytes + salt
    hashed_data = hashlib.sha256(data_with_salt).hexdigest()
    return hashed_data

def encrypt_data(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    if isinstance(data, str):
        data = data.encode('utf-8')

    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data

def decrypt_data(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def main():
    password = input("Password:")
    data_to_encrypt = input("Data:")
    salt = generate_salt()
    key = generate_key(password, salt)
    iv = secrets.token_bytes(16)

    hashed_data = hash_data(data_to_encrypt, salt)
    encrypted_data = encrypt_data(hashed_data, key, iv)

    print("Encryption was successful.")

    decrypted_data = decrypt_data(encrypted_data, key, iv)
    decrypted_data_hashed = hash_data(data_to_encrypt, salt)
    print("Decryption was successfull.")

    #print(hashed_data)
    #print(decrypted_data_hashed)

    if decrypted_data_hashed.lower() == hashed_data.lower():
        print("Data integrity verified.")
    else:
        print("Data integrity compromised.")

if __name__ == "__main__":
    main()
