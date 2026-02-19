"""
encryption.py

A custom implementation of RSA-OAEP (SHA-256 + MGF1)
combined with AES-256-GCM for hybrid encryption (of large data).

Features:

- 2048-bit RSA key generation
- OAEP padding (SHA-256)
- AES-256-GCM for large data encryption

WARNING:
This implementation is for educational purposes only.

DO NOT USE IN PRODUCTION

"""

from . import prime_checker
import math
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class RSA_KeyPair:

    """
    
    Generates a 2048-bit RSA key pair for encryption/decryption.

    Attributes:

        public_key (list): [e, n] RSA public key

        private_key (list): [d, n] RSA private key

    
    
    """


    def __init__(self):

        NUM_BITS = 2048

        p = prime_checker.generate_prime(NUM_BITS // 2)

        q = prime_checker.generate_prime(NUM_BITS // 2)

        n = p * q

        totient = (p - 1) * (q - 1)

        e = 65537


        while math.gcd(e, totient) != 1:

            p = prime_checker.generate_prime(NUM_BITS // 2)

            q = prime_checker.generate_prime(NUM_BITS // 2)

            n = p * q

            totient = (p - 1) * (q - 1)

        d = pow(e, -1, totient)

        assert (d * e) % totient == 1


        self.public_key = [e, n]

        self.private_key = [d, n]



class RSA_DecryptionError(Exception):

    """ Raised when RSA-OAEP decryption fails. """


def _prepare_message(message, n: int) -> bytes:

    k = (n.bit_length() + 7) // 8

    lHash = hashlib.sha256(b'').digest()

    hLen = len(lHash)

    MAX_MESSAGE_LEN = k - 2 * hLen - 2


    if isinstance(message, str):

        message_bytes = message.encode("utf-8")

    elif isinstance(message, bytes):

        message_bytes = message

    else:

        raise TypeError("message argument must be str or bytes")

    if len(message_bytes) <= MAX_MESSAGE_LEN:

        return _encode_message(_add_padding(message_bytes, k, hLen, lHash), hLen)
    
    else:

        raise ValueError("Data too large. Use encrypt_large_data() for larger data")



def _mfg1(seed: bytes, mask_len: int) -> bytes:

    T = b""

    counter = 0

    while len(T) < mask_len:

        C = counter.to_bytes(4, "big")

        T += hashlib.sha256(seed + C).digest()

        counter += 1

    return T[:mask_len]



def _add_padding(message_bytes: bytes, k: int, hLen: int, lHash: bytes) -> bytes:

    ps_length = k - len(message_bytes) - 2 * hLen - 2

    ps = b'\x00' * ps_length

    db = lHash + ps + b'\x01' + message_bytes

    assert len(db) == k - hLen - 1

    return db


def _encode_message(db: bytes, hLen: int) -> bytes:

    seed = secrets.token_bytes(hLen)

    db_mask = _mfg1(seed, len(db))

    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    seed_mask = _mfg1(masked_db, hLen)

    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    encoded_message = b'\x00' + masked_seed + masked_db

    return encoded_message



def _decode_message(encoded_message: bytes, hLen: int, k: int) -> bytes:

    masked_seed = encoded_message[1:1 + hLen]

    masked_db = encoded_message[1 + hLen:]

    assert len(masked_seed) == hLen

    assert len(masked_db) == k - hLen - 1

    seed_mask = _mfg1(masked_db, hLen)

    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = _mfg1(seed, k - hLen - 1)

    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    return db


def encrypt_message(message: str, public_key_pair: list) -> bytes:

    """
    
    Encrypt a small message using RSA-OAEP with SHA-256.


    Args:

        message (str): The message to encrypt. Must fit in a single RSA block.

        public_key_pair (list): RSA public key [e, n].


    Returns:

        bytes: The RSA-OAEP encrypted ciphertext.
    
    
        
    Raises:

        TypeError: If the message is not str or bytes.

        ValueError: If the message is too long to fit in one RSA block.

    
    
    
    """






    k = (public_key_pair[1].bit_length() + 7) // 8

    encoded_message = _prepare_message(message, public_key_pair[1])

    message_int = int.from_bytes(encoded_message, "big")

    cipher_int = pow(message_int, public_key_pair[0], public_key_pair[1])

    cipher_text = cipher_int.to_bytes(k, "big")

    return cipher_text



def decrypt_message(encrypted_text: bytes, private_key_pair: list) -> bytes:


    """
    
    Decrypt a small message using RSA-OAEP with SHA-256.


    Args:

        encrypted_text (str): The message to decrypt.

        private_key_pair (list): RSA private key [d, n].


    Returns:

        bytes: The decrypted message.
    
    
        
    Raises:

        RSA_DecryptionError: If the decryption fails due to initial byte check or hash check

    
    
    
    """






    k = (private_key_pair[1].bit_length() + 7) // 8

    lHash = hashlib.sha256(b'').digest()

    hLen = len(lHash)


    cipher_int = int.from_bytes(encrypted_text, "big")

    message_int = pow(cipher_int, private_key_pair[0], private_key_pair[1])

    encoded_message = message_int.to_bytes(k, "big")


    if encoded_message[0] != 0:

        raise RSA_DecryptionError("Intial byte check failed")

    db = _decode_message(encoded_message, hLen, k)

    lHash_check = db[:hLen]


    if lHash_check != lHash:

        raise RSA_DecryptionError("Hash check failed")

    rest = db[hLen:]

    index = rest.index(b'\x01')

    message = rest[index + 1:]


    return message


def encrypt_large_data(data: str, public_key_pair: list) -> bytes:

    """
    Encrypt a large message using hybrid encryption (RSA + AES-GCM).

    Process:

        1. Generate a random 32-byte AES-256 key.

        2. Encrypt the data with AES-256-GCM using the AES key.

        3. Encrypt the AES key with RSA-OAEP.

        4. Combine the encrypted AES key, nonce, and AES ciphertext.

    Args:

        data (str): The message to encrypt.

        public_key_pair (list): RSA public key [e, n].

    Returns:

        bytes: Combined encrypted key + nonce + AES ciphertext.

    """




    key = secrets.token_bytes(32)

    nonce = secrets.token_bytes(12)

    aesgcm = AESGCM(key)

    cipher_text = aesgcm.encrypt(nonce, data.encode("utf-8"), None)

    encrypted_key = encrypt_message(key, public_key_pair)


    return encrypted_key + nonce + cipher_text



def decrypt_large_data(encrypted_data: bytes, private_key_pair: list) -> bytes:

    """
    Decrypt a large message.

    Process:

        1. Get the encrypted AES key.

        2. Decrypt the AES key with RSA-OAEP

        3. Decrypt the data with AES-256-GCM using AES key

        4. Return the decrypted key

    Args:

        encrypted_data (str): The message to decrypt.

        private_key_pair (list): RSA private key [d, n].

    Returns:

        bytes: The decrypted data.

    """

    rsa_block_size = 256

    encrypted_key = encrypted_data[:rsa_block_size]

    nonce = encrypted_data[rsa_block_size: rsa_block_size + 12]

    cipher_text = encrypted_data[rsa_block_size + 12:]

    key = decrypt_message(encrypted_key, private_key_pair)

    assert len(key) == 32

    aesgcm = AESGCM(key)

    data = aesgcm.decrypt(nonce, cipher_text, None)


    return data



if __name__ == "__main__":
    
    rsakey_pair = RSA_KeyPair()

    decrypted = decrypt_large_data(encrypt_large_data("Hello", rsakey_pair.public_key), rsakey_pair.private_key)

    print(decrypted.decode("utf-8"))
