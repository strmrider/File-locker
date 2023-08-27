# File-locker
File encryption library

## Features
* Encryption and decryption of files
* Includes key verification
* File name encryption
* Includes compression
* Includes detection of unwanted data alteration

## Usage
* **``encrypt_file(path, cipher_key, output, new_name, compress, add_signature)``**
  
  Encrypts a file. Receives target file's path, cipher key, output path (optional), new name (optional), compression and signature flags.
  
* **``decrypt_file(path, cipher_key, output)``**
  
  Decrypts a file. Receives encrypted file's path, cipher key, and output path (optional)
  
```python
from locker import encrypt_file, decrypt_file
key = os.urandom(16)
path = 'C://doc/test.txt'
cipher_name = str(uuid.uuid4()) # generates random name

# encrypt file
# no output path (overrides file), new cipher name, includes compression and signature
encrypt_file(path, key, None, cipher_name, True, True)
# decrypt file
path = f'C://doc/{cipher_name}' # encrypted file path
# decrypts and overrides current file (no output path)
decrypt_file(path, key, None)
```
Verify whether a file was encrypted with a certain key
```python
from locker verify_key
result = verify_key(path, key) # returns True if key is correct
```
#### File header
The file's header contains data about the encrypted file such as the original file's data and encryption properties
```python
from locker extract_file_header
header = extract_file_header(path, cipher_key) # returns 'FileHeader' object
# original file's info
data = header.info # return 'FileData' object
```
##### Attributes
* info: FileData object
* nonce: A randomly generated nonce associated with the file.
* signature: The digital signature of the file.
* checksum: The checksum value of the file for data integrity verification.
* hide_name: A flag indicating whether the original file name is hidden.
* compressed: A flag indicating whether the file is compressed.

##### FileData attributes
Original file's information
* id: The unique identifier for the file.
* filename: The name of the file.
* encrypt_date: The date when the file was encrypted.
* file_size: The size of the file in bytes.

### Exceptions
* HeaderError: Raised when there is an issue with the file header during processing.
* CipherError: Raised when a cipher-related error occurs during decryption.
* AuthenticationError: Raised when authentication fails during a secure operation.

