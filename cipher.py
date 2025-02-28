from cryptography.fernet import Fernet
import os

class FileEncryptorDecryptor:
    def __init__(self, key=None):
        """Initialize the encryptor/decryptor with a key."""
        self.key = key

    def generate_key(self):
        """Generate a new encryption key."""
        self.key = Fernet.generate_key()
        print(f"Generated Key: {self.key.decode()}")
        return self.key

    def save_key_to_file(self, filename="secret.key"):
        """Save the encryption key to a file."""
        if not self.key:
            raise ValueError("No key available. Generate or load a key first.")
        with open(filename, "wb") as key_file:
            key_file.write(self.key)
        print(f"Key saved to {filename}")

    def load_key_from_file(self, filename="secret.key"):
        """Load the encryption key from a file."""
        with open(filename, "rb") as key_file:
            self.key = key_file.read()
        print(f"Key loaded from {filename}")

    def encrypt_file(self, input_file, output_file=None):
        """Encrypt a text file."""
        if not self.key:
            raise ValueError("No key available. Generate or load a key first.")
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file '{input_file}' not found.")

        fernet = Fernet(self.key)
        with open(input_file, "rb") as file:
            file_data = file.read()

        encrypted_data = fernet.encrypt(file_data)

        if not output_file:
            output_file = input_file + ".encrypted"

        with open(output_file, "wb") as file:
            file.write(encrypted_data)
        print(f"File encrypted and saved as {output_file}")

    def decrypt_file(self, input_file, output_file=None):
        """Decrypt a text file."""
        if not self.key:
            raise ValueError("No key available. Generate or load a key first.")
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file '{input_file}' not found.")

        fernet = Fernet(self.key)
        with open(input_file, "rb") as file:
            encrypted_data = file.read()

        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except Exception as e:
            raise ValueError("Decryption failed. Invalid key or file.")

        if not output_file:
            output_file = input_file.replace(".encrypted", "") + ".decrypted"

        with open(output_file, "wb") as file:
            file.write(decrypted_data)
        print(f"File decrypted and saved as {output_file}")

def main():
    print("File Encryption/Decryption Tool")
    tool = FileEncryptorDecryptor()

    while True:
        print("\nOptions:")
        print("1. Generate a new key")
        print("2. Load key from file")
        print("3. Encrypt a file")
        print("4. Decrypt a file")
        print("5. Exit")
        choice = input("Enter your choice: ")

        try:
            if choice == "1":
                tool.generate_key()
                save_key = input("Do you want to save the key to a file? (y/n): ").lower()
                if save_key == "y":
                    key_file = input("Enter the filename to save the key (default: secret.key): ") or "secret.key"
                    tool.save_key_to_file(key_file)

            elif choice == "2":
                key_file = input("Enter the filename to load the key from (default: secret.key): ") or "secret.key"
                tool.load_key_from_file(key_file)

            elif choice == "3":
                input_file = input("Enter the input file to encrypt: ")
                output_file = input("Enter the output file (leave blank to use default): ")
                tool.encrypt_file(input_file, output_file)

            elif choice == "4":
                input_file = input("Enter the input file to decrypt: ")
                output_file = input("Enter the output file (leave blank to use default): ")
                tool.decrypt_file(input_file, output_file)

            elif choice == "5":
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please try again.")

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()