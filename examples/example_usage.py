"""

Example usage of the encryption library.


"""

from src.encryption import RSA_KeyPair, encrypt_message, decrypt_message, encrypt_large_data, decrypt_large_data


# Generate RSA key pair
keypair = RSA_KeyPair()

# --- Simple message encryption ---
msg = "Hello, world!"

cipher = encrypt_message(msg, keypair.public_key)

print("Encrypted (bytes):", cipher)

decrypted = decrypt_message(cipher, keypair.private_key)

print("Decrypted:", decrypted)

# --- Large data encryption ---
large_data = "This is a long message that we want to encrypt using hybrid RSA + AES."

encrypted_data = encrypt_large_data(large_data, keypair.public_key)

print("Encrypted large data length:", len(encrypted_data))

decrypted_data = decrypt_large_data(encrypted_data, keypair.private_key)

print("Decrypted large data:", decrypted_data)
