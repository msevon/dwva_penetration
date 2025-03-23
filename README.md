# Cybersecurity Testing Toolkit

A collection of security testing tools designed for educational purposes and penetration testing practice against DVWA (Damn Vulnerable Web Application).

## Features

- **Brute Force Attack**: Automated password brute forcing against DVWA login
- **SQL Injection**: Automated SQL injection testing with various payloads
- **Password Decryption**: MD5 hash cracking using rainbow table approach

## Prerequisites

- Python 3.x
- DVWA running locally (http://localhost/dvwa)
- Required Python packages:
  - requests
  - beautifulsoup4
  - tqdm

## Project Structure

```
cybsec/
├── src/
│   ├── tool.py          # Main entry point
│   ├── brute.py         # Brute force implementation
│   ├── sql_inject.py    # SQL injection testing
│   ├── decrypt.py       # Password decryption
│   └── output/          # Output directory for results
├── resources/
│   ├── 10k.txt                         # Password dictionary
│   ├── SQL_injection_payloads.txt      # SQL injection patterns
│   └── SQL_injection_payload_passwords.txt
```

## Usage

1. Ensure DVWA is running locally
2. Run the complete toolkit:
   ```
   python src/tool.py
   ```

Or run individual modules:
```
python src/brute.py      # For brute force only
python src/sql_inject.py # For SQL injection testing
python src/decrypt.py    # For password decryption
```

## Security Notice

⚠️ This toolkit is designed for educational purposes and should only be used against systems you have permission to test. Unauthorized testing against systems you don't own or have permission to test is illegal.

## Output

- Brute force results are displayed in real-time
- SQL injection findings are saved to the output directory
- Decrypted passwords are saved as CSV files in the output directory 