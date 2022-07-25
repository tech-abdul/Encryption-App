from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os, sys, shutil

def write_bytes_to_file(filename, bytes):
    file_handler_write = open(filename, "wb")
    file_handler_write.write(bytes)
    file_handler_write.close()

def read_bytes_from_file(filename):
    file_handler_read = open(filename, "rb")
    contents = file_handler_read.read()
    file_handler_read.close()
    return contents

# Hardcoded secret_code reused for private key and session key <Vulnerability>
# Keep the secret code 16 characters since it is also used by AES

secret_code = "0123456789012345"
public_key_name = "public_key.pem"
rsa_key_name = "rsa_key.pem"

def generate_key(secret_code = secret_code, output_rsa_key_name = rsa_key_name, output_public_key_name = public_key_name):
    # Function for public and private key generation
    key = RSA.generate(2048)
    # RSA (private) key generation
    rsa_key = key.export_key(passphrase=secret_code, pkcs=8, protection="scryptAndAES128-CBC")
    write_bytes_to_file(filename=output_rsa_key_name, bytes=rsa_key)
    print("Your RSA key has been saved as {}".format(output_rsa_key_name))
    print("*"*50)
    print("Your RSA key password is {}".format(secret_code))
    print("*"*50)
    # Public key generation
    public_key = key.publickey().export_key()
    write_bytes_to_file(filename=output_public_key_name, bytes=public_key)
    print("Your public key has been saved as {}\n".format(output_public_key_name))
    print("Key generation complete")

def import_private_key(key_file_name, key_password = secret_code):
    # Function for reading a private key
    encoded_key = open(key_file_name, "rb").read()
    private_key = RSA.import_key(encoded_key, passphrase=key_password)
    public_key = private_key.publickey().export_key()
    return (private_key, public_key)

def encrypt(input_file, public_key_bytes, session_key_bytes):
    print("\nBeginning encryption")
    # First create the RSA cipher using the public key
    public_key = RSA.import_key(public_key_bytes)
    rsa_cipher = PKCS1_OAEP.new(public_key)
    # Then encrypt the session key using the public key
    encrypted_session_key = rsa_cipher.encrypt(session_key_bytes)
    # Then encrypt the input file data using:
    # 1. the encrypted session key
    # 2. AES.MODE_EAX to allow for authentication in case of tampering
    aes_cipher = AES.new(session_key_bytes, AES.MODE_EAX)
    if not is_file(input_file):
        zip_and_delete_folder(folder_name=input_file)
        input_file = input_file + ".zip"
        print("Folder compressed to archive: {}".format(input_file))
    input_data = read_bytes_from_file(filename=input_file)
    ciphertext, tag = aes_cipher.encrypt_and_digest(input_data)
    output_file = input_file + ".bin"
    file_out = open(output_file, "wb")
    [ file_out.write(x) for x in (encrypted_session_key, aes_cipher.nonce, tag, ciphertext) ]
    file_out.close()
    os.remove(input_file)
    print("{} deleted.\nEncryption complete.\nOutput file name: {}".format(input_file, output_file))

def decrypt(input_file, private_key, password):
    print("\nBeginning decryption")
    # First create the RSA cipher using the public key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    # Then get the encrypted content from the file
    input_data = open(input_file, "rb")
    enc_session_key, nonce, tag, ciphertext = [ input_data.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    input_data.close()
    # Then decrypt and verify the session key
    session_key_bytes = cipher_rsa.decrypt(enc_session_key)
    if (session_key_bytes.decode() == password): print("Password accepted")
    else:
        print("Incorrect password")
        sys.exit(1)
    # Then recreate the AES cipher and decrypt the ciphertext
    cipher_aes = AES.new(session_key_bytes, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    output_file = input_file[0:(len(input_file) - 4)]
    write_bytes_to_file(filename=output_file, bytes=data)
    os.remove(input_file)
    print("{} deleted.\nDecryption complete.\nOutput file name: {}".format(input_file, output_file))

def is_file(file_name):
    # Function to check whether input is a file or folder.
    # Returns True if it is a file, False otherwise (folder)
    return os.path.isfile(file_name)

def zip_and_delete_folder(folder_name):
    # Function to zip a folder and delete the original folder
    shutil.make_archive(folder_name, "zip", folder_name)
    shutil.rmtree(folder_name)

def padPassword(inputPassword, expectedLength=16, paddingCharacter="0"):
    output = inputPassword
    while len(output) < expectedLength:
        output = paddingCharacter + output
    return output

def get_16_char_password(password):
    if (len(password) > 16): return password[0:16]
    else: return padPassword(password)

def main():
    print("\nCustom Encryption Program\n")
    choice_a = int(input("Enter 1 for encryption or 2 for decryption\n"))
    if (choice_a == 1):
        # The user selected encryption
        choice_b = int(input("Enter 1 to generate keys or 2 if you already generated the keys\n"))

        if (choice_b == 1):
            # The user wants to generate keys
            generate_key()
        
        # The user already has the keys
        pub_key = str(input("Enter the name of your public key\n"))
        input_file = str(input("Enter the name of the file / folder to encrypt\n"))
        enc_password = get_16_char_password(str(input("Enter the encryption password to use <max 16 characters>\n")))
        encrypt(input_file=input_file, public_key_bytes=read_bytes_from_file(pub_key), session_key_bytes = enc_password.encode())

    elif (choice_a == 2):
        # The user selected decryption
        priv_key = str(input("Enter the name of your RSA (private) key\n"))
        priv_key_password = str(input("Enter the password of your RSA (private) key\n"))
        (private_key, _) = import_private_key(key_file_name=priv_key, key_password=priv_key_password)
        input_file = str(input("Enter the name of the file to decrypt\n"))
        dec_password = get_16_char_password(str(input("Enter the decryption password\n")))
        decrypt(input_file=input_file, private_key=private_key, password=dec_password)

if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as error:
        print(error)
        print("Ensure you type the file name with its extension [Case sensitive]")
    except ValueError as error:
        print(error)
        print("Invalid password for the private key or session key")
    except:
        print("Uncaught exception")