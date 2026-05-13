

import hashlib

def generate_md5(text):

    text_bytes = text.encode("utf-8")

    # create the MD5 hash
    md5_hash = hashlib.md5(text_bytes)

    # return the hash as a readable hex string
    return md5_hash.hexdigest()


def generate_sha1(text):
    """
    Generate a SHA1 hash from the given text.
    SHA1 produces a 40-character hex string.
    """
    text_bytes = text.encode("utf-8")

    sha1_hash = hashlib.sha1(text_bytes)

    return sha1_hash.hexdigest()


def generate_sha256(text):
    """""
    Generate a SHA256 hash from the given text.
    SHA256 produces a 64-character hex string.
    """
    text_bytes = text.encode("utf-8")

    sha256_hash = hashlib.sha256(text_bytes)

    return sha256_hash.hexdigest()


def generate_all_hashes(text):

   # generates all hashes at once and returns them

    results = {
        "input": text,
        "MD5": generate_md5(text),
        "SHA1": generate_sha1(text),
        "SHA256": generate_sha256(text),
    }
    return results


