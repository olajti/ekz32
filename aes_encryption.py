# Симетричне шифрування AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac
import os

# Генерація ключа для AES
password = b'my_strong_password'  # Замініть на ваш пароль
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256 біт для AES-256
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

# Генерація вектора ініціалізації (IV)
iv = os.urandom(16)  # 128 біт для AES

# Шифрування даних
data = "Текст для шифрування".encode('utf-8')
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Доповнення даних (Padding)
padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

# Шифрування
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Додавання MAC
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(encrypted_data)
mac = h.finalize()

# Збереження шифрованих даних та MAC
print(f"Encrypted data: {encrypted_data}")
print(f"MAC: {mac}")

# Дешифрування
# Перевірка MAC
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(encrypted_data)
h.verify(mac)

# Дешифрування
decryptor = cipher.decryptor()
decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

# Видалення доповнення
unpadder = padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
print(f"Decrypted data: {decrypted_data.decode()}")

# ------------------------------------------------------------------------------------------------------

# Асиметричне шифрування RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Генерація пари ключів RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Збереження приватного та публічного ключів
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(f"Private Key: {pem_private.decode()}")
print(f"Public Key: {pem_public.decode()}")

# Шифрування даних
data_to_encrypt = b"Текст для шифрування RSA"
encrypted_data_rsa = public_key.encrypt(
    data_to_encrypt,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Encrypted data RSA: {encrypted_data_rsa}")

# Підписання даних
signature = private_key.sign(
    data_to_encrypt,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(f"Signature: {signature}")

# Дешифрування та перевірка підпису
decrypted_data_rsa = private_key.decrypt(
    encrypted_data_rsa,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Decrypted data RSA: {decrypted_data_rsa.decode()}")

# Перевірка підпису
public_key.verify(
    signature,
    data_to_encrypt,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Signature is valid!")