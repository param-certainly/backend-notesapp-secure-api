Private Note-Taking System
==========================

Overview
--------
This repository contains a backend implementation for a private note-taking system using Python's cryptography library. The system provides secure storage and retrieval of notes, ensuring confidentiality and integrity through encryption and authentication mechanisms.

Key Features
-------------

^Secure Note Storage: Notes are encrypted using AES-GCM, ensuring confidentiality and integrity.
Password-Based Key Derivation: Uses PBKDF2HMAC for deriving keys from passwords, providing robust protection against brute-force attacks.

^Nonce Generation: Nonces are derived using a counter and part of the derived key, ensuring unique nonces for each encryption operation.

^Integrity Verification: Includes integrity tags for encrypted notes, ensuring data integrity upon decryption.

^Access Logging: Logs access and removal operations for notes.

Usage
-----
^Initialization
---------------

#Create an Instance: Initialize the PrivNotes class with a password. This will generate a salt and derive a key.

#Add Notes: Use the set method to add notes. Notes are encrypted and stored with a derived nonce and integrity tag.

#Fetch Notes: Use the get method to retrieve notes. The method decrypts the note and verifies its integrity.

#Remove Notes: Use the remove method to delete notes. Successful removal is logged.

Serialization and Deserialization
---------------------------------

^Dump: Use the dump method to serialize the note data and generate a checksum.

^Load: Initialize a new PrivNotes instance with the serialized data and checksum to load the notes.

Security Considerations
-----------------------

^Password Security: The system relies on a secure password for key derivation. Use strong, unique passwords.

^Data Integrity: The system verifies data integrity upon decryption. Any integrity failures will raise exceptions.

Example Usage
-------------

python
from private_notes import PrivNotes

# Initialize notes with a password
priv_notes = PrivNotes('123456')

# Add notes
kvs = {
    'Groceries': 'lettuce\nbread\nchocolate',
    'Idea': 'We will take a forklift to the moon!',
    'Secrets': 'The secret word is bananas.'
}
for title in kvs:
    priv_notes.set(title, kvs[title])

# Fetch notes
for title in kvs:
    note = priv_notes.get(title)
    if note != kvs[title]:
        print(f"Error fetching note: {title}")

# Remove notes
if not priv_notes.remove('Groceries'):
    print("Error removing note: Groceries")

# Serialize notes
data, checksum = priv_notes.dump()

# Load notes
new_notes_instance = PrivNotes('123456', data, checksum)

Dependencies
------------

^cryptography: For cryptographic primitives (AES-GCM, PBKDF2HMAC, HMAC).

^pickle: For serialization and deserialization of note data.

^hashlib: For generating checksums and integrity tags.

License
-------
This project is licensed under the MIT License. See LICENSE for details.

Contributing
------------

Contributions are welcome. Please submit pull requests with detailed descriptions of changes.

Contact
-------

For any questions or feedback, please contact psch.10000@gmail.com. Thank you for using the Private Note-Taking System. Ensure to handle passwords securely and keep the system updated with the latest security patches.
