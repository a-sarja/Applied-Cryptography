import argparse
# import traceback
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as padding_asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import crypto_utils
import file_utils


class CryptoClass:

    def __init__(self, my_privatekey_filepath, target_publickey_filepath, plaintext_filepath, encrypted_filepath):

        # password = b'CY6740' # If your private-keys need some password, please update the password here and uncomment this line (and comment the line 17)
        password = None
        self.my_private_key = crypto_utils.read_private_key(filepath=my_privatekey_filepath, password=password)
        self.target_public_key = crypto_utils.read_public_key(filepath=target_publickey_filepath)
        self.target_filepath = plaintext_filepath
        self.encrypted_filepath = encrypted_filepath
        self.VERIFICATION_FAILED = -1
        self.VERIFICATION_SUCCESS = 0

    # Function to perform Symmetric Encryption using a secret key (32 byte = 256 bit) and IV (16 byte = 128 bit)
    def encrypt_symmetric(self, plain_text):

        if not self.my_private_key:
            raise Exception("[Custom Exception] Error in reading the private/public key. Please try again..")

        # Before encrypting the plain text, sign it using sender's private key
        s_sign = self.sign_payload(payload=plain_text)
        if not s_sign:
            raise Exception("[Custom Exception] Error in signing the payload. Please try again...")

        plain_text = crypto_utils.get_padded_data(content=plain_text)
        # Generate the secret key and initialization vector for symmetric encryption
        secret_key, initial_vector = crypto_utils.generate_secret_key_iv()
        cipher = Cipher(
            algorithm=algorithms.AES(secret_key),
            mode=modes.CBC(initialization_vector=initial_vector),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(plain_text) + encryptor.finalize()
        return secret_key, initial_vector, s_sign, cipher_text

    # Function to perform Symmetric Decryption using the `shared_secret` and `shared initialization_v`
    def decrypt_symmetric(self, cipher_text, shared_secret, shared_iv):

        cipher = Cipher(
            algorithm=algorithms.AES(shared_secret),
            mode=modes.CBC(initialization_vector=shared_iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()
        decrypted_text = crypto_utils.get_unpadded_data(content=decrypted_text)

        # decrypted_text is supposed to be in plain text
        return file_utils.write_file(filepath=self.target_filepath, content=decrypted_text)

    # Function to perform asymmetrical encryption using receiver's public key (happens on the sender's side)
    def encrypt_asymmetric(self, payload, symmetric_encrypted_data, signature):

        if not self.target_public_key:
            raise Exception("[Custom Exception] Error in reading the receiver's public key. Please try again..")

        encrypted_content = self.target_public_key.encrypt(
            payload,
            padding_asymmetric.OAEP(
                mgf=padding_asymmetric.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return file_utils.write_file(filepath=self.encrypted_filepath, content=encrypted_content + signature + symmetric_encrypted_data)

    # Function to perform asymmetric decryption using receiver's private key (happens on the receiver's side)
    def decrypt_asymmetric(self):

        if not self.my_private_key:
            raise Exception("[Custom Exception] Error in reading the private key. Please try again..")

        payload_asymmetric_encrypted = file_utils.read_file(filepath=self.encrypted_filepath)
        if not payload_asymmetric_encrypted:
            raise Exception("[Custom Exception] File does not exist..")

        # Retrieve the sender_signature, and symmetrically encrypted data
        signature = payload_asymmetric_encrypted[512:1024]
        data_for_symmetric_decryption = payload_asymmetric_encrypted[1024:]
        payload_asymmetric_encrypted = payload_asymmetric_encrypted[:512]

        asymmetric_decrypted_content = self.my_private_key.decrypt(
            payload_asymmetric_encrypted,
            padding_asymmetric.OAEP(
                mgf=padding_asymmetric.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return asymmetric_decrypted_content, signature, data_for_symmetric_decryption

    def sign_payload(self, payload):

        signature = self.my_private_key.sign(
            payload,
            padding_asymmetric.PSS(
                mgf=padding_asymmetric.MGF1(hashes.SHA256()),
                salt_length=padding_asymmetric.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )

        return signature

    def verify_signature(self, signature, payload):

        try:
            self.target_public_key.verify(
                signature,
                payload,
                padding_asymmetric.PSS(
                    mgf=padding_asymmetric.MGF1(hashes.SHA256()),
                    salt_length=padding_asymmetric.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return self.VERIFICATION_SUCCESS

        except cryptography.exceptions.InvalidSignature as exception:
            print("Error in verifying the signature. - " + str(exception))

        return self.VERIFICATION_FAILED


if __name__ == '__main__':

    # Read these from arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", action="append", required=False, help="Encryption parameter", nargs=4)
    parser.add_argument("-d", "--decrypt", action="append", required=False, help="Decryption parameter", nargs=4)

    args = parser.parse_args()

    try:
        if args.encrypt:
            print("Encryption process started...")

            input_arguments = args.encrypt[0]
            if len(args.encrypt[0]) < 4:
                raise Exception("[Custom Exception] Invalid number of arguments..")

            receiver_public_key_path = input_arguments[0]
            sender_private_key_path = input_arguments[1]
            plain_textfile_path = input_arguments[2]
            cipher_textfile_path = input_arguments[3]
            crypto_object = CryptoClass(my_privatekey_filepath=sender_private_key_path, target_publickey_filepath=receiver_public_key_path, plaintext_filepath=plain_textfile_path, encrypted_filepath=cipher_textfile_path)

            file_content = file_utils.read_file(filepath=plain_textfile_path)  # Plain text to be encrypted
            s_key, i_vector, s_signature, c_text = crypto_object.encrypt_symmetric(plain_text=file_content)
            payload_for_asymmetric_encryption = s_key + i_vector  # Payload structure: [32 byte secret-key][16 byte i_v]

            result = crypto_object.encrypt_asymmetric(payload=payload_for_asymmetric_encryption, symmetric_encrypted_data=c_text, signature=s_signature)
            print("Process completed... You can find the encrypted ciphertext file at " + str(result))

        if args.decrypt:
            print("Decryption process started...")

            input_arguments = args.decrypt[0]
            if len(args.decrypt[0]) < 4:
                raise Exception("[Custom Exception] Invalid number of arguments..")

            receiver_private_key_path = input_arguments[0]
            sender_public_key_path = input_arguments[1]
            cipher_textfile_path = input_arguments[2]
            target_filepath = input_arguments[3]

            decrypto_object = CryptoClass(my_privatekey_filepath=receiver_private_key_path, target_publickey_filepath=sender_public_key_path, plaintext_filepath=target_filepath, encrypted_filepath=cipher_textfile_path)

            # [asymmetrically-encrypted-secret][asymmetrically-encrypted-iv][signature][symmetrically-encrypted-message]
            decrypted_content, sender_signature, symmetric_data = decrypto_object.decrypt_asymmetric()
            s_key = decrypted_content[0:32]
            s_iv = decrypted_content[32:48]

            result = decrypto_object.decrypt_symmetric(cipher_text=symmetric_data, shared_secret=s_key, shared_iv=s_iv)

            # Verify the sender signature
            decrypted_plaintext = file_utils.read_file(filepath=result)
            sign_verification = decrypto_object.verify_signature(signature=sender_signature, payload=decrypted_plaintext)
            if sign_verification == decrypto_object.VERIFICATION_SUCCESS:
                print("Signature verified..")
            else:
                # Delete/remove the file if the signature verification fails
                file_utils.delete_file(filepath=result)
                raise Exception("[Custom Exception] Signature verification failed..")

            print("Process completed... You can find the decrypted plaintext file at " + str(result))

    except Exception as ex:
        print("Process terminated with some exception - " + str(ex))
        # traceback.print_exception(ex)
