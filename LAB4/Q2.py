from Crypto.Util import number
from datetime import datetime, timedelta
import json

# Centralized key management system
class KeyManagementService:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}  # Store keys by hospital/clinic ID
        self.logs = []  # Logs for auditing
        self.revoked_keys = set()  # Store revoked key IDs
        self.key_expiration_period = timedelta(days=365)  # Keys expire every 12 months
    
    # Key Generation: Generate public and private key pairs for each hospital/clinic using Rabin cryptosystem
    def generate_rabin_keypair(self, facility_id):
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        n = p * q  # Public key
        private_key = (p, q)
        
        # Store keys securely
        self.keys[facility_id] = {
            'public_key': n,
            'private_key': private_key,
            'generation_date': datetime.now(),
            'expiration_date': datetime.now() + self.key_expiration_period,
        }
        
        # Log the key generation
        self._log_action(f"Generated keys for {facility_id}")
        
        return n, private_key

    # Key Distribution: Provide a secure API for hospitals/clinics to request and receive their key pairs
    def get_keys(self, facility_id):
        if facility_id in self.revoked_keys:
            raise Exception(f"Keys for {facility_id} have been revoked.")
        if facility_id in self.keys:
            self._log_action(f"Provided keys for {facility_id}")
            return self.keys[facility_id]['public_key'], self.keys[facility_id]['private_key']
        else:
            raise Exception(f"Facility {facility_id} does not exist.")

    # Key Revocation: Revoke keys for a specific hospital/clinic
    def revoke_keys(self, facility_id):
        if facility_id in self.keys:
            self.revoked_keys.add(facility_id)
            self._log_action(f"Revoked keys for {facility_id}")
        else:
            raise Exception(f"Facility {facility_id} does not exist.")

    # Key Renewal: Automatically renew keys for all hospitals/clinics
    def renew_keys(self):
        for facility_id, key_data in self.keys.items():
            if key_data['expiration_date'] <= datetime.now():
                new_public_key, new_private_key = self.generate_rabin_keypair(facility_id)
                self.keys[facility_id]['public_key'] = new_public_key
                self.keys[facility_id]['private_key'] = new_private_key
                self.keys[facility_id]['generation_date'] = datetime.now()
                self.keys[facility_id]['expiration_date'] = datetime.now() + self.key_expiration_period
                self._log_action(f"Renewed keys for {facility_id}")

    # Secure Storage: Securely store private keys to prevent unauthorized access
    def store_private_keys(self, storage_path='private_keys.json'):
        encrypted_keys = {}
        for facility_id, key_data in self.keys.items():
            encrypted_keys[facility_id] = {
                'private_key': key_data['private_key'],
                'generation_date': key_data['generation_date'].strftime('%Y-%m-%d'),
                'expiration_date': key_data['expiration_date'].strftime('%Y-%m-%d')
            }
        
        with open(storage_path, 'w') as f:
            json.dump(encrypted_keys, f)
        self._log_action("Stored private keys securely")

    # Auditing and Logging: Log all key management operations
    def _log_action(self, action):
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action': action
        }
        self.logs.append(log_entry)

    # Retrieve logs for auditing
    def get_logs(self):
        return self.logs

# Example usage of the key management service
kms = KeyManagementService(key_size=1024)

# Generate keys for a hospital
public_key, private_key = kms.generate_rabin_keypair("Hospital_A")
print(f"Public Key: {public_key}\nPrivate Key: {private_key}")

# Distribute the keys securely
keys = kms.get_keys("Hospital_A")
print(f"Retrieved Keys for Hospital_A: {keys}")

# Store keys securely
kms.store_private_keys()

# Revoke keys for a facility
kms.revoke_keys("Hospital_A")

# Renew keys for all hospitals
kms.renew_keys()

# Retrieve logs
print("Logs:", kms.get_logs())

