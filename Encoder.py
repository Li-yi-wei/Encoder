from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
#todo decode增加直接傳base64文字的功能

class KeyGenerate:
    def __init__(self, public_exponent = 65537, key_size = 2048):
        self.public_exponent = public_exponent
        self.key_size = key_size

    def genkey(self):
        self.private_key = rsa.generate_private_key(
            public_exponent = self.public_exponent,
            key_size = self.key_size
        )
        self.public_key = self.private_key.public_key()

    def key_save_pem(self):
        self.private_key_pem = self.private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        )

        self.public_key_pem = self.public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("private_key.pem", "wb") as private_key_file:
            private_key_file.write(self.private_key_pem)

        with open("public_key.pem", "wb") as public_key_file:
            public_key_file.write(self.public_key_pem)  

class Encoder:
    def __init__(self):
        pass

    def encode(self, message, public_key_file_path, save = True):
        with open(public_key_file_path, "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read())
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        if save:
            with open("ciphertext.bin", "wb") as cipherfile:
                cipherfile.write(ciphertext)

        return ciphertext

    def decode(self, ciphertext_file_path, private_key_file_path, save = True):
        with open(private_key_file_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(private_key_file.read(), password = None)

        with open(ciphertext_file_path, "rb") as ciphertext_file:
            ciphertext = ciphertext_file.read()

            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf = padding.MGF1(algorithm = hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label = None
                )
            )

        if save:
            with open("plaintext.txt", "wb") as plainfile:
                plainfile.write(plaintext)
        
        return plaintext
        

