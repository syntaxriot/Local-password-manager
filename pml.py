from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import json
import os
import getpass

DATA_FILE = 'passwords.json'

class PasswordManager:
    def __init__(self):
        self.data = {}
        self.fernet = None

    def load_data(self, password):
        if not os.path.exists(DATA_FILE):
            self.initialize_data(password)
        else:
            with open(DATA_FILE, 'r') as f:
                self.data = json.load(f)
            
            salt = base64.b64decode(self.data['salt'])
            key = self._generate_key(password, salt)
            self.fernet = Fernet(key)
            
            # Verify master password
            try:
                verified = self.fernet.decrypt(self.data['verification'].encode()).decode()
                if verified != 'verified':
                    raise ValueError("Invalid master password")
            except:
                raise ValueError("Invalid master password")

    def initialize_data(self, password):
        salt = os.urandom(16)
        key = self._generate_key(password, salt)
        self.fernet = Fernet(key)
        
        verification = self.fernet.encrypt(b'verified').decode()
        self.data = {
            'salt': base64.b64encode(salt).decode(),
            'verification': verification,
            'entries': []
        }
        self._save_data()

    def _generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _save_data(self):
        with open(DATA_FILE, 'w') as f:
            json.dump(self.data, f, indent=4)

    def add_entry(self, service, username, password):
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        self.data['entries'].append({
            'service': service,
            'username': username,
            'password': encrypted_password
        })
        self._save_data()

    def get_entries(self, service=None):
        entries = []
        for entry in self.data['entries']:
            if service is None or entry['service'] == service:
                decrypted_password = self.fernet.decrypt(entry['password'].encode()).decode()
                entries.append({
                    'service': entry['service'],
                    'username': entry['username'],
                    'password': decrypted_password
                })
        return entries

def main():
    print("=== Local password manager ===")
    pm = PasswordManager()

    if not os.path.exists(DATA_FILE):
        print("\nFirst-time setup: Create a master password")
        while True:
            master_pw = getpass.getpass("Create master password: ")
            confirm_pw = getpass.getpass("Confirm master password: ")
            if master_pw == confirm_pw:
                break
            print("Error: Passwords don't match. Try again.\n")
        pm.load_data(master_pw)
        print("\nMaster password set up successfully!")
    else:
        master_pw = getpass.getpass("\nEnter master password: ")
        try:
            pm.load_data(master_pw)
        except ValueError as e:
            print(f"\nError: {e}")
            return

    while True:
        print("\nMenu:")
        print("1. Store new password")
        print("2. Retrieve password")
        print("3. List all services")
        print("4. Exit")
        choice = input("Enter choice (1-4): ").strip()

        if choice == '1':
            service = input("Service name: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ").strip()
            pm.add_entry(service, username, password)
            print("\nPassword stored successfully!")

        elif choice == '2':
            service = input("Service name to retrieve: ").strip()
            entries = pm.get_entries(service)
            if entries:
                print("\nMatching entries:")
                for idx, entry in enumerate(entries, 1):
                    print(f"{idx}. Service: {entry['service']}")
                    print(f"   Username: {entry['username']}")
                    print(f"   Password: {entry['password']}")
            else:
                print("\nNo entries found for this service.")

        elif choice == '3':
            entries = pm.get_entries()
            if entries:
                print("\nStored services:")
                for entry in entries:
                    print(f"- {entry['service']}")
            else:
                print("\nNo passwords stored yet.")

        elif choice == '4':
            print("\nExiting Local password manager. Goodbye!")
            break

        else:
            print("\nInvalid choice. Please enter 1-4.")

if __name__ == '__main__':
    main()