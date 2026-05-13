# core/password_checker.py
# Checks how strong a password is
# Gives score, strength label, and tips to improve

def check_strength(password):
    """Check password strength and return score + feedback"""
    
    score = 0
    feedback = []
    
    # Check length
    if len(password) >= 12:
        score += 2
        feedback.append("✅ Good length (12+ characters)")
    elif len(password) >= 8:
        score += 1
        feedback.append("⚠️ Decent length (8-11 characters)")
    else:
        feedback.append("❌ Too short (less than 8 characters)")
    
    # Check uppercase
    if any(c.isupper() for c in password):
        score += 1
        feedback.append("✅ Contains uppercase letters")
    else:
        feedback.append("❌ Missing uppercase letters")
    
    # Check lowercase
    if any(c.islower() for c in password):
        score += 1
        feedback.append("✅ Contains lowercase letters")
    else:
        feedback.append("❌ Missing lowercase letters")
    
    # Check numbers
    if any(c.isdigit() for c in password):
        score += 1
        feedback.append("✅ Contains numbers")
    else:
        feedback.append("❌ Missing numbers")
    
    # Check special characters
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if any(c in special for c in password):
        score += 1
        feedback.append("✅ Contains special characters")
    else:
        feedback.append("❌ Missing special characters")
    
    # Check common passwords
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "abc123"]
    if password.lower() in common:
        score = 0
        feedback = ["🚨 This is a VERY common password! Easily guessable."]
    
    # Determine strength label
    if score >= 5:
        strength = "Strong"
        color = "green"
    elif score >= 3:
        strength = "Medium"
        color = "orange"
    else:
        strength = "Weak"
        color = "red"
    
    return {
        "password": password,
        "score": score,
        "max_score": 6,
        "strength": strength,
        "color": color,
        "feedback": feedback
    }


# Test
if __name__ == "__main__":
    print("=" * 50)
    print("PASSWORD STRENGTH CHECKER TEST")
    print("=" * 50)
    
    test_passwords = ["abc", "password123", "MyP@ssw0rd!", "Str0ng!P@ss#2024"]
    
    for pwd in test_passwords:
        result = check_strength(pwd)
        print(f"\nPassword: {pwd}")
        print(f"Strength: {result['strength']} ({result['score']}/{result['max_score']})")
        for fb in result['feedback']:
            print(f"  {fb}")