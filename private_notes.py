#Param Shrikant Chaudhari
#PID: 730696802
#Programming Assignment 1


import os
import pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import hmac

class PrivNotes:
  MAX_NOTE_LEN = 2048;

  def __init__(self, password, data = None, checksum = None):
    self.salt = os.urandom(16) if data is None else None  # Generate salt only for new instances
    self.key = self._derive_key(password)
    self.nonce_counter = 0  # Initialize a counter for nonces

    if data is not None:
        # Verify checksum if provided
        if checksum is not None:
            calculated_checksum = hashlib.sha256(bytes.fromhex(data)).hexdigest()
            if calculated_checksum != checksum:
                raise ValueError("Invalid checksum")

        # Deserialize data
        try:
            self.kvs = pickle.loads(bytes.fromhex(data))
        except Exception as e:
            raise ValueError("Malformed serialized format") from e

        # Check if the password is correct by attempting to decrypt a sample note
        try:
            for title, encrypted_note in self.kvs.items():
                aesgcm = AESGCM(self.key)
                aesgcm.decrypt(encrypted_note['nonce'], encrypted_note['data'], None)
                break  
        except Exception as e:
            raise ValueError("Incorrect password")
    else:
        self.kvs = {}

  def _derive_nonce(self):
    # Derive a nonce using the counter and part of the derived key
    nonce_material = (self.nonce_counter.to_bytes(8, 'little') +
                      self.key[:4])  # Use part of the key as additional material
    self.nonce_counter += 1
    return nonce_material

  def _derive_key(self, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=self.salt,
        iterations=2000000,
    )
    return kdf.derive(password.encode('ascii'))

  def dump(self):
    serialized_data = pickle.dumps(self.kvs)
    checksum = hashlib.sha256(serialized_data).hexdigest()
    hex_encoded_data = serialized_data.hex()
    
    return hex_encoded_data, checksum


  def get(self, title):
    hmac_key = hmac.HMAC(self.key, hashes.SHA256())
    hmac_key.update(title.encode('ascii'))
    encoded_title = hmac_key.finalize()

    encrypted_note = self.kvs.get(encoded_title)
    if encrypted_note is None:
        return None

    aesgcm = AESGCM(self.key)
    try:
        decrypted_note = aesgcm.decrypt(
            encrypted_note['nonce'],
            encrypted_note['data'],
            None
        ).decode('ascii')

        # Verify integrity tag
        expected_integrity_tag = hashlib.sha256(title.encode('ascii') + decrypted_note.encode('ascii')).hexdigest()
        if encrypted_note['integrity'] != expected_integrity_tag:
            raise ValueError("Integrity check failed")

        # Log access
        self.access_log.append((title, 'get'))

        return decrypted_note
    except Exception as e:
        return None

  def set(self, title, note):
    if len(note) > self.MAX_NOTE_LEN:
        raise ValueError('Maximum note length exceeded')

    hmac_key = hmac.HMAC(self.key, hashes.SHA256())
    hmac_key.update(title.encode('ascii'))
    encoded_title = hmac_key.finalize()

    aesgcm = AESGCM(self.key)
    nonce = self._derive_nonce()  # Use derived nonce
    encrypted_note = aesgcm.encrypt(nonce, note.encode('ascii'), None)

    # Create an integrity tag
    integrity_tag = hashlib.sha256(title.encode('ascii') + note.encode('ascii')).hexdigest()

    # Store the encrypted note, nonce, and integrity tag in the key-value store
    self.kvs[encoded_title] = {
        'nonce': nonce,
        'data': encrypted_note,
        'integrity': integrity_tag
    }

  def remove(self, title):
    hmac_key = hmac.HMAC(self.key, hashes.SHA256())
    hmac_key.update(title.encode('ascii'))
    encoded_title = hmac_key.finalize()

    if encoded_title in self.kvs:
        del self.kvs[encoded_title]
        
        # Log removal
        self.access_log.append((title, 'remove'))

        return True

    return False
