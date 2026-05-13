# core/caesar_cipher.py
# Caesar Cipher - simple encryption and decryption
# Shifts each letter by a chosen key number

def encrypt(text, key):
    """Encrypt text using Caesar cipher with given key"""
    result = ""
    
    for char in text:
        if char.isupper():
            # Shift uppercase letters (A=65, Z=90)
            new_char = chr((ord(char) - 65 + key) % 26 + 65)
            result += new_char
        elif char.islower():
            # Shift lowercase letters (a=97, z=122)
            new_char = chr((ord(char) - 97 + key) % 26 + 97)
            result += new_char
        else:
            # Keep spaces and symbols unchanged
            result += char
    
    return result


def decrypt(text, key):
    """Decrypt text - just encrypt with negative key"""
    return encrypt(text, -key)


def brute_force_decrypt(text):
    """Try all 26 possible keys to crack the cipher"""
    results = []
    
    for key in range(26):
        decrypted = decrypt(text, key)
        results.append({"key": key, "text": decrypted})
    
    return results


# Test
if __name__ == "__main__":
    print("=" * 50)
    print("CAESAR CIPHER TEST")
    print("=" * 50)
    
    original = "Hello World"
    key = 3
    
    encrypted = encrypt(original, key)
    decrypted = decrypt(encrypted, key)
    
    print(f"\nOriginal:  {original}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    
    print("\nBrute Force Attack (trying all keys):")
    for result in brute_force_decrypt(encrypted):
        if "Hello" in result['text']:
            print(f"  Key {result['key']:2d}: {result['text']} ✅ FOUND!")