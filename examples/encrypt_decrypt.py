from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

# Load the completed RSA private key from a PEM file
def load_rsa_private_key(pem_path):
    with open(pem_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

# Decrypt a ciphertext with the private key
def decrypt_with_private_key(private_key, ciphertext):
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

def main():
    private_key_path = 'complete_private_key.pem'
    encrypted_message_path = 'encrypted_message.txt'  # path to the Base64-encoded ciphertext file

    # Load the private key
    private_key = load_rsa_private_key(private_key_path)

    # Load and decode the encrypted message
    with open(encrypted_message_path, 'rb') as f:
        encrypted_data = base64.b64decode(f.read())

    # Decrypt the message
    decrypted_message = decrypt_with_private_key(private_key, encrypted_data)

    # Output the decrypted message
    print("Decrypted message:", decrypted_message.decode())

if __name__ == "__main__":
    main()
