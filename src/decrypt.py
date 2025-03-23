import hashlib
import csv
import os
from tqdm import tqdm

def generate_rainbow_table():
    print("\n" + "="*50)
    print("GENERATING RAINBOW TABLE")
    print("="*50 + "\n")
    
    # Load passwords from 10k.txt file
    try:
        with open('../resources/10k.txt', 'r') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        print("[ERROR] Password file '../resources/10k.txt' not found")
        return {}
    except Exception as e:
        print(f"[ERROR] Reading password file: {str(e)}")
        return {}
    
    rainbow_table = {}
    print(f"Processing {len(passwords)} passwords...")
    for password in tqdm(passwords, desc="Building rainbow table", unit="password"):
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        rainbow_table[md5_hash] = password
    
    return rainbow_table

def decrypt_passwords():
    print("\n" + "="*50)
    print("PASSWORD DECRYPTION")
    print("="*50 + "\n")
    
    input_file = '../output/dvwa_credentials.csv'
    output_file = '../output/dvwa_plaintext_credentials.csv'
    
    if not os.path.exists(input_file):
        print(f"[ERROR] Input file {input_file} not found")
        return
        
    # Generate rainbow table
    rainbow_table = generate_rainbow_table()
    if not rainbow_table:
        return
        
    decrypted_credentials = []
    
    print("\nDecrypting passwords...")
    # Read and attempt to decrypt passwords
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f, delimiter=';')
        rows = list(reader)
        for row in tqdm(rows, desc="Decrypting", unit="credential"):
            username = row['username']
            md5_hash = row['password']
            
            # Look up the hash in our rainbow table
            plain_password = rainbow_table.get(md5_hash, 'NOT_FOUND')
            decrypted_credentials.append((username, plain_password))
    
    # Write decrypted credentials to new file        
    with open(output_file, 'w', newline='') as f:
        f.write("username;password\n")
        for username, password in decrypted_credentials:
            f.write(f"{username};{password}\n")
    
    # Print summary
    print("\n" + "="*50)
    print("DECRYPTION SUMMARY")
    print("="*50)
    print(f"\n[SUCCESS] Decrypted credentials saved to: {output_file}")
    
    successful_decryptions = [cred for cred in decrypted_credentials if cred[1] != 'NOT_FOUND']
    print(f"\nSuccessfully decrypted passwords: {len(successful_decryptions)}/{len(decrypted_credentials)}")
    
    if successful_decryptions:
        print("\nDecrypted Credentials:")
        for username, password in successful_decryptions:
            print(f"[+] Username: {username}, Password: {password}")
    
    if len(successful_decryptions) < len(decrypted_credentials):
        print("\n[NOTE] Entries marked as 'NOT_FOUND' indicate the password hash wasn't in our rainbow table.")
    print("\n" + "="*50)

if __name__ == "__main__":
    decrypt_passwords()
