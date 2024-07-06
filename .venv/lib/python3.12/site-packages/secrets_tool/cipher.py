"""
Implementing custom encryption, as the default "fernet" method from the cryptography package
uses random initialization numbers, which cause a different encrypted string for identical content all the time.

We don't need message authentication in our case, and changing strings would be annoying in Git.
"""
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(data: bytes, key: bytes, iv_bytes: bytes) -> bytes:
    """
    data can be bytes of arbitrary length
    key must be 32 bytes long
    iv_bytes can be of arbitrary length, as they will be hashed
    """
    iv_digest = hashes.Hash(hashes.SHA256(), default_backend())
    iv_digest.update(iv_bytes)
    iv = iv_digest.finalize()[:16]

    algorithm = algorithms.AES(key)
    mode = modes.CBC(iv)

    cipher = Cipher(algorithm, mode=mode, backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithm.block_size).padder()
    to_encrypt = padder.update(iv + data) + padder.finalize()

    encrypted = encryptor.update(to_encrypt) + encryptor.finalize()
    return base64.b64encode(encrypted)


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    data should be encrypted binary, encoded as base64 - as it is produced by 'encrypt()'
    key must be 32 bytes long
    """

    data = base64.b64decode(data)
    iv = data[:16]
    message = data[16:]

    algorithm = algorithms.AES(key)
    mode = modes.CBC(iv)

    cipher = Cipher(algorithm, mode=mode, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(message) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted
