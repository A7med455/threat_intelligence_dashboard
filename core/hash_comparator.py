import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from same folder (core/)
from hashmap_generator import generate_all_hashes


def compare_hashes(text1, text2):
    """Compare hashes of two different strings"""
    
    hashes1 = generate_all_hashes(text1)
    hashes2 = generate_all_hashes(text2)
    
    differences = {}
    
    for algo in ["MD5", "SHA1", "SHA256"]:
        hash1 = hashes1[algo]
        hash2 = hashes2[algo]
        
        # Count how many characters are different
        diff_count = sum(1 for a, b in zip(hash1, hash2) if a != b)
        diff_percentage = (diff_count / len(hash1)) * 100
        
        differences[algo] = {
            "hash1": hash1,
            "hash2": hash2,
            "diff_count": diff_count,
            "diff_percentage": round(diff_percentage, 2)
        }
    
    return {
        "input1": text1,
        "input2": text2,
        "differences": differences
    }


def avalanche_effect(base_text):
    """Show how changing one character changes the entire hash"""
    
    # Change first character
    if len(base_text) > 0:
        if base_text[0] == 'a':
            new_char = 'b'
        elif base_text[0] == 'A':
            new_char = 'B'
        else:
            new_char = 'x'
        modified_text = new_char + base_text[1:]
    else:
        modified_text = base_text + "x"
    
    original = generate_all_hashes(base_text)
    modified = generate_all_hashes(modified_text)
    
    results = {}
    
    for algo in ["MD5", "SHA1", "SHA256"]:
        orig_hash = original[algo]
        mod_hash = modified[algo]
        
        # Count different characters
        diff_chars = sum(1 for a, b in zip(orig_hash, mod_hash) if a != b)
        diff_percentage = (diff_chars / len(orig_hash)) * 100
        
        results[algo] = {
            "original": orig_hash,
            "modified": mod_hash,
            "diff_chars": diff_chars,
            "diff_percentage": round(diff_percentage, 2)
        }
    
    return {
        "original_input": base_text,
        "modified_input": modified_text,
        "avalanche_results": results
    }


# Test code
if __name__ == "__main__":
    print("\n" + "="*50)
    print("Hash Comparator Test")
    print("="*50)
    
    # Test 1: Compare two different strings
    print("\n1. Comparing 'Hello' and 'Hello!'")
    print("-" * 30)
    
    result1 = compare_hashes("Hello", "Hello!")
    
    for algo, data in result1["differences"].items():
        print(f"\n{algo}:")
        print(f"  '{result1['input1']}': {data['hash1']}")
        print(f"  '{result1['input2']}': {data['hash2']}")
        print(f"  Different: {data['diff_count']}/{len(data['hash1'])} ({data['diff_percentage']}%)")
    
    # Test 2: Avalanche effect
    print("\n" + "="*50)
    print("2. Avalanche Effect - One character change")
    print("="*50)
    
    result2 = avalanche_effect("Hello")
    
    print(f"\nOriginal: '{result2['original_input']}'")
    print(f"Modified: '{result2['modified_input']}'")
    
    for algo, data in result2["avalanche_results"].items():
        print(f"\n{algo}:")
        print(f"  Original: {data['original']}")
        print(f"  Modified: {data['modified']}")
        print(f"  Different: {data['diff_chars']}/{len(data['original'])} ({data['diff_percentage']}%)")
        
        # Check if avalanche effect is good
        if data['diff_percentage'] > 50:
            print(f"  ✅ Good avalanche effect")
        else:
            print(f"  ⚠️ Moderate avalanche effect")
    
    print("\n" + "="*50)
    print("Done - Comparator ready")
    print("="*50 + "\n")