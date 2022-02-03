import hashlib

def file_as_bytes(file):
    with file:
        return file.read()

def perform_hashing(fname):
    return hashlib.md5(file_as_bytes(open(fname, 'rb'))).hexdigest()
    
