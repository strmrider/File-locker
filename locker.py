from Crypto.Cipher import AES
from hashlib import sha256
import struct
import pickle
import uuid
import os
import zlib
import warnings
from datetime import datetime

#########################
# Errors and exceptions #
#########################

WRONG_KEY_ERROR = "Wrong cipher key is provided"
HEADER_ERROR = "File header might be corrupted"
NOT_USED_BY_APP_ERROR = "The file is not encrypted by the app"


class HeaderError(Exception):
    def __init__(self, message):
        self.message = f'File Header Error: {message}'


class AuthenticationError(Exception):
    def __init__(self, message):
        self.message = f'Authentication failed: {message}'


class CipherError(Exception):
    def __init__(self, message):
        self.message = f'Cipher error: {message}'


###############
# Dataclasses #
###############


class FileData:
    """
    Contains target File's data, includes its original name, size and
     encryption date
    """
    def __init__(self, id, filename, size, date):
        self.id = id
        self.filename = filename
        self.encrypt_date = date
        self.file_size = size

    def __str__(self):
        return f'ID: {self.id}\n' \
               f'filename: {self.filename}\n' \
               f'size: {self.file_size}\n' \
               f'encryption time: {str(self.encrypt_date)}'


class FileHeader:
    """
    Encrypted file's header. Saved in the encrypted file and contains its
    encryption data for decryption purposes.
    Can also be fetched from the file without decryption (useful for learning
    about the file's encryption properties)
    """
    def __init__(self, file_info: FileData, nonce: bytes, signature: bytes,
                 checksum: bytes, compressed: bool, hide_name: bool):
        """
        :param file_info: Original file's data
        :param nonce: bytes; encryption's nonce
        :param signature: bytes; encryption's signature
        :param checksum: bytes: encrypted data checksum
        :param compressed: bool; compression option
        :param hide_name: bool; original name hiding option
        """
        self.info = file_info
        self.nonce = nonce
        self.signature = signature
        self.checksum = checksum
        self.hide_name: bool = hide_name
        self.compressed = compressed


def fletcher_checksum(data, key_size):
    if key_size not in (8, 16, 32):
        raise Exception('Key must be 8, 16 or 32')
    sum1, sum2 = int(), int()
    for index in range(len(data)):
        sum1 = (sum1 + data[index]) % 2**key_size
        sum2 = (sum2 + sum1) % 2**key_size
    return (sum2 << key_size) | sum1


##############
# Operations #
##############


def encrypt_data(data: any, cipher_key: bytes, add_signature: bool) -> tuple:
    """
    Encrypts data
    :param data: bytes; target data to be encrypted
    :param cipher_key: bytes; encryption key
    :param add_signature: bool; sign encryption option
    :return: tuple; nonce and the encrypted data
    """
    aes = AES.new(cipher_key, AES.MODE_EAX)
    if add_signature:
        ciphertext, tag = aes.encrypt_and_digest(data)
        return aes.nonce, tag, ciphertext
    else:
        ciphertext = aes.encrypt(data)
        return aes.nonce, ciphertext


def decrypt_data(data: bytes, cipher_key: bytes,
                 signature: bytes, nonce: bytes) -> bytes:
    """
    Decrypts encrypted data.
    Throws AuthenticationError and CipherError exceptions
    :param data: bytes; encrypted data
    :param cipher_key: bytes; encryption key
    :param signature: bytes or None; encryption's signature
    :param nonce: bytes; encryption's nonce
    :return: bytes; decrypted data
    """
    aes = AES.new(cipher_key, AES.MODE_EAX, nonce)
    try:
        decrypted_data = aes.decrypt(data)
        if signature:
            try:
                aes.verify(signature)
            except ValueError:
                raise AuthenticationError(
                    "Failed to verify signature.\n"
                    "Key might be wrong or the signature is corrupted")
        return decrypted_data
    except ValueError:
        raise CipherError('Decryption failed')


def build_header(cipher_key: bytes, file_info: FileData, nonce: bytes,
                 signature: bytes, checksum: bytes,
                 compress: bool, hide_name: bool) -> bytes:
    """
    Builds encrypted file header
    :param cipher_key: bytes; encryption key
    :param file_info: FileData;
    :param nonce: bytes; encryption's nonce
    :param signature: bytes or None; encryption's signature
    :param checksum: bytes: encrypted data checksum
    :param compress: bool; compression option
    :param hide_name: bool; original name hiding option
    :return: bytes: file's header
    """
    file_header = \
        FileHeader(file_info, nonce, signature, checksum, compress, hide_name)
    file_header = pickle.dumps(file_header)
    header_nonce, header_tag, cipher_header = \
        encrypt_data(file_header, cipher_key, True)
    header_checksum = sha256(cipher_header).digest()
    header_body = header_nonce + header_tag + header_checksum + cipher_header
    compressed_header = zlib.compress(header_body, 2)
    total_header_size = 7 + len(compressed_header)
    header = struct.pack(
        '!I B B B I', total_header_size, len(header_nonce), len(header_tag),
        len(header_checksum), len(cipher_header))
    header += compressed_header
    return header


def dissect_header(header: bytes, cipher_key: bytes) -> FileHeader:
    """
    Dissects the header from the file.
    Throws AuthenticationError exception.
    prints a warning if the header doesn't match its own checksum
    (this doesn't necessarily mean that the header is corrupted, might be a checksum
    corruption instead, while the header can be still valid)
    :param header: bytes; header read from file in raw bytes
    :param cipher_key: bytes;  file's encryption key
    :return: FileHeader
    """
    try:
        nonce_len, signature_len, checksum_len, file_header_len = \
            struct.unpack("!B B B I", header[:7])
    except struct.error as e:
        raise HeaderError(f'Failed to read Header. {HEADER_ERROR}') from e
    header = zlib.decompress(header[7:])
    cursor = 0
    nonce = header[cursor:cursor+nonce_len]
    cursor += nonce_len
    signature = header[cursor:cursor+signature_len]
    cursor += signature_len
    checksum = header[cursor:cursor+checksum_len]
    cursor += checksum_len
    cipher_file_header = header[cursor: cursor+file_header_len]
    if sha256(cipher_file_header).digest() != checksum:
        warnings.warn(f'Checksum error. {HEADER_ERROR}')
    try:
        file_header = \
            decrypt_data(cipher_file_header, cipher_key, signature, nonce)
        file_header = pickle.loads(file_header)
        return file_header
    except AuthenticationError:
        raise AuthenticationError(f"""This might be of the following reasons:\n
                                  "1. {WRONG_KEY_ERROR}.\n "
                                  "2. {HEADER_ERROR}\n "
                                  "3. {NOT_USED_BY_APP_ERROR}""")


def read_header(cipher_file, cipher_key):
    try:
        header_len = struct.unpack("!I", cipher_file.read(4))[0]
        header = cipher_file.read(header_len)
        return dissect_header(header, cipher_key)
    except struct.error:
        raise HeaderError(
            'Could not read header size.\n'
            'Header is not in the correct format; '
            'might be because it was not encrypted'
            'by the app or the file was corrupted)


def extract_file_header(path: str, cipher_key: bytes) -> FileHeader:
    """
    Extracts header from file
    :param path: file's path
    :param cipher_key: encryption key
    :return: FileHeader: file's header
    """
    with open(path, 'rb+') as cipher_file:
        header = read_header(cipher_file, cipher_key)
        return header


def verify_key(path: str, cipher_key: bytes) -> bool:
    """
    Verifies if a file was encrypted by a given key
    :param path: str; file path
    :param cipher_key: bytes; the subjected cipher key
    :return: bool;
    """
    try:
        header = extract_file_header(path, cipher_key)
        return header is not None
    except:
        return False


def encrypt_file(path: str, cipher_key: bytes, output: str, new_name: str,
                 compress: bool, add_signature: bool) -> None:
    """
    Encrypts a file
    :param path: str; file's path
    :param cipher_key: bytes; encryption key
    :param output: str; target encrypted file
    :param new_name: str; new encrypted file name, in case the target file is
    the current original one
    :param compress: bool; file compression option
    :param add_signature: bool; sign encryption (recommended)
    """
    hide_name = output == '' and new_name != ''
    _file = open(path, 'rb+')
    data = _file.read()
    file_info = FileData(str(uuid.uuid4()), os.path.basename(path),
                         len(data), datetime.now())
    nonce, signature, cipher_data = \
        encrypt_data(data, cipher_key, add_signature)
    checksum = sha256(cipher_data).digest()
    if compress:
        cipher_data = zlib.compress(cipher_data, 2)
    header = build_header(cipher_key, file_info, nonce, signature,
                          checksum, compress, hide_name)
    target_file = open(output, 'wb+') if output else _file
    target_file.seek(0)
    target_file.write(header)
    target_file.write(cipher_data)
    target_file.truncate()
    _file.close()
    target_file.close()
    if hide_name:
        new_name = os.path.join(os.path.dirname(path), new_name)
        os.rename(path, new_name)


def decrypt_file(path: str, cipher_key: bytes, output: str) -> None:
    """
    Decrypts a file.
    Throws AuthenticationError and CipherError exceptions
    :param path: str; encrypted file path
    :param cipher_key: bytes; encryption key
    :param output: str; target decrypted file
    """
    cipher_file = open(path, 'rb+')
    header = read_header(cipher_file, cipher_key)
    cipher_data = cipher_file.read(-1)
    if header.compressed:
        cipher_data = zlib.decompress(cipher_data)
    data = \
        decrypt_data(cipher_data, cipher_key, header.signature, header.nonce)
    output_file = open(output, 'wb+') if output else cipher_file
    output_file.seek(0)
    output_file.write(data)
    output_file.truncate()
    cipher_file.close()
    output_file.close()
    if header.hide_name:
        new_name = os.path.join(os.path.dirname(path), header.info.filename)
        os.rename(path, new_name)
