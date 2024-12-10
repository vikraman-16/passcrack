import itertools
from hashlib import sha256

# Generate password list (optimized to return a generator to save memory)
def generate_passwords(chars, length):
    return (''.join(p) for p in itertools.product(chars, repeat=length))

# Hash a password
def hash_password(password):
    return sha256(password.encode()).hexdigest()

# Brute force passwords
def brute_force(hash, chars, length):
    for password in generate_passwords(chars, length):
        if hash_password(password) == hash:
            print("Password found:", password)
            return
        # Optionally, add feedback on progress
        # print(f"Trying: {password}")
    print("Password not found.")

# Check password strength
def password_strength(password):
    if len(password) < 8:
        print("Weak")
    elif any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password):
        print("Strong")
    else:
        print("Moderate")

# Dictionary attack
def dictionary_attack(hash, file):
    try:
        with open(file, 'r') as f:
            for line in f:
                word = line.strip()
                if hash_password(word) == hash:
                    print("Password found:", word)
                    return
            print("Password not found in dictionary.")
    except FileNotFoundError:
        print(f"Error: File {file} not found.")

def main():
    print("Password Cracking Toolkit")
    while True:
        print("\n1. Check password strength")
        print("2. Perform dictionary attack")
        print("3. Perform brute force attack")
        print("4. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            password = input("Enter a password: ")
            password_strength(password)
        elif choice == "2":
            hash = input("Enter the password hash: ")
            file = input("Enter dictionary file path: ")
            dictionary_attack(hash, file)
        elif choice == "3":
            hash = input("Enter the password hash: ")
            chars = input("Enter characters to use (e.g., abc123!): ")
            length = int(input("Enter password length: "))
            brute_force(hash, chars, length)
        elif choice == "4":
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
