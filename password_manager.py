# Developed by Jeronimo Junior (JJSETECH)
import os
import shutil
import sqlite3
import argparse
from getpass import getpass

from cryptography.fernet import Fernet
import secrets
import string
import hashlib
import tkinter as tk
from tkinter import messagebox

# --- Constants ---
DB_FILE = "passwords.db"
KEY_FILE = "key.key"
MASTER_HASH_FILE = "master.hash"

# --- Encryption Helpers ---
def generate_key():
    """Generate and save a key for encryption."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    """Load the encryption key from the key file."""
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def encrypt(data, key):
    """Encrypt data using the provided key."""
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt(data, key):
    """Decrypt data using the provided key."""
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

# --- Master Password Helpers ---
def hash_master_password(password):
    """Hash the master password using SHA-256."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)

def set_master_password():
    """Set a new master password and save its hash."""
    if os.path.exists(MASTER_HASH_FILE):
        print("Master password is already set.")
        return
    master_password = getpass("Set a new master password: ")
    confirm_password = getpass("Confirm master password: ")
    if master_password != confirm_password:
        print("Passwords do not match. Try again.")
        return
    hashed = hash_master_password(master_password)
    with open(MASTER_HASH_FILE, "wb") as hash_file:
        hash_file.write(hashed)
    print("Master password set successfully!")

def verify_master_password():
    """Verify the entered master password against the saved hash."""
    if not os.path.exists(MASTER_HASH_FILE):
        print("Master password is not set. Please set it first.")
        set_master_password()
        return True
    master_password = getpass("Enter master password: ")
    hashed = hash_master_password(master_password)
    with open(MASTER_HASH_FILE, "rb") as hash_file:
        stored_hash = hash_file.read()
    if hashed != stored_hash:
        print("Incorrect master password. Access denied.")
        return False
    return True

# --- Database Helpers ---
def init_db():
    """Initialize the database if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

def add_password(service, username, password, key):
    """Add a new password to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    encrypted_password = encrypt(password, key)
    cursor.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)", (service, username, encrypted_password))
    conn.commit()
    conn.close()

def get_passwords(key):
    """Retrieve and decrypt all passwords."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT service, username, password FROM passwords")
    rows = cursor.fetchall()
    conn.close()

    decrypted_rows = []
    for service, username, password in rows:
        decrypted_password = decrypt(password, key)
        decrypted_rows.append((service, username, decrypted_password))
    return decrypted_rows

def delete_password(service):
    """Delete a password for a specific service."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
    conn.commit()
    conn.close()

# --- Backup and Restore ---
def backup_database():
    """Create a backup of the database."""
    backup_file = DB_FILE + ".backup"
    shutil.copy(DB_FILE, backup_file)
    print(f"Backup created: {backup_file}")

def restore_database():
    """Restore the database from a backup."""
    backup_file = DB_FILE + ".backup"
    if not os.path.exists(backup_file):
        print("No backup file found.")
        return
    shutil.copy(backup_file, DB_FILE)
    print("Database restored from backup.")

# --- Password Generation ---
def generate_password(length=12):
    """Generate a secure random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))


# --- Password Strength Checker ---
def check_password_strength(password):
    """Evaluate the strength of a password."""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    strength = 0
    if length >= 8: strength += 1
    if has_upper: strength += 1
    if has_lower: strength += 1
    if has_digit: strength += 1
    if has_special: strength += 1

    if strength == 5:
        return "Strong"
    elif strength >= 3:
        return "Moderate"
    else:
        return "Weak"

# --- Search Functionality ---
def search_password(service, key):
    """Search for passwords by service name."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT service, username, password FROM passwords WHERE service LIKE ?", (f"%{service}%",))
    rows = cursor.fetchall()
    conn.close()

    decrypted_rows = []
    for service, username, password in rows:
        decrypted_password = decrypt(password, key)
        decrypted_rows.append((service, username, decrypted_password))
    return decrypted_rows

# --- GUI Integration ---
def launch_gui():
    """Launch a Tkinter GUI for the password manager."""
    key = load_key()

    def center_main_screen(app, width, height):
        app.update_idletasks()
        screen_width = app.winfo_screenwidth()
        screen_height = app.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        return x, y

    def center_and_resize_window(window, app, width, height):
        app.update_idletasks()  # Ensures window size is updated
        screen_width = app.winfo_screenwidth()
        screen_height = app.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")

    def add_entry():
        # Custom pop-up window for adding entries
        def submit():
            service = service_var.get()
            username = username_var.get()
            password = password_var.get()
            if service and username and password:
                add_password(service, username, password, key)
                messagebox.showinfo("Success", f"Password for {service} added successfully!")
                popup.destroy()
            else:
                messagebox.showwarning("Error", "All fields are required!")

        popup = tk.Toplevel()
        popup.title("Add Entry")
        center_and_resize_window(popup, app, 300, 300)
        popup.grab_set()  # Make the pop-up modal

        tk.Label(popup, text="Service:").pack(pady=5)
        service_var = tk.StringVar()
        tk.Entry(popup, textvariable=service_var).pack(pady=5)

        tk.Label(popup, text="Username:").pack(pady=5)
        username_var = tk.StringVar()
        tk.Entry(popup, textvariable=username_var).pack(pady=5)

        tk.Label(popup, text="Password:").pack(pady=5)
        password_var = tk.StringVar()
        tk.Entry(popup, textvariable=password_var, show="*").pack(pady=5)

        tk.Button(popup, text="Submit", command=submit).pack(pady=10)
        tk.Button(popup, text="Cancel", command=popup.destroy).pack(pady=5)

    def view_entries():
        # Custom pop-up window for viewing entries
        popup = tk.Toplevel()
        popup.title("View Entries")
        center_and_resize_window(popup, app, 600, 320)
        popup.grab_set()  # Make the pop-up modal

        # Frame to hold the Text widget and Scrollbar
        frame = tk.Frame(popup)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create a Text widget with a vertical scrollbar
        text = tk.Text(frame, wrap=tk.WORD, height=15, width=35)
        scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)

        # Place Text widget and scrollbar side-by-side
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Retrieve and display password entries
        passwords = get_passwords(key)
        if not passwords:
            text.insert(tk.END, "No passwords found.")
        else:
            entries = "\n".join([f"Service: {s}, Username: {u}, Password: {p}" for s, u, p in passwords])
            text.insert(tk.END, entries)

        # Disable editing in the Text widget
        text.config(state=tk.DISABLED)

        # Close button
        tk.Button(popup, text="Close", command=popup.destroy).pack(pady=10)

    def search_entry():
        # Custom pop-up window for searching entries
        def search():
            service = service_var.get()
            if service:
                results = search_password(service, key)
                if not results:
                    messagebox.showinfo("Info", "No matching passwords found.")
                else:
                    entries = "\n".join([f"Service:  {s}\nUsername:  {u}\nPassword:  {p}" for s, u, p in results])
                    results_var.set(entries)
            else:
                messagebox.showwarning("Error", "Please enter a service name.")

        popup = tk.Toplevel()
        popup.title("Search Entry")
        center_and_resize_window(popup, app, 300, 300)
        popup.grab_set()  # Make the pop-up modal

        tk.Label(popup, text="Enter Service Name:").pack(pady=5)
        service_var = tk.StringVar()
        tk.Entry(popup, textvariable=service_var).pack(pady=5)

        tk.Button(popup, text="Search", command=search).pack(pady=10)
        results_var = tk.StringVar()
        tk.Label(popup, textvariable=results_var, wraplength=280, justify=tk.LEFT).pack(pady=10, padx=10)

        tk.Button(popup, text="Close", command=popup.destroy).pack(pady=5)

    app = tk.Tk()
    app.title("Password Manager")

    # Set main window size and center it
    #app.geometry("350x120")
    # Define the desired dimensions of the popup
    popup_width = 350
    popup_height = 120
    x, y = center_main_screen(app, popup_width, popup_height)
    app.geometry(f"{popup_width}x{popup_height}+{x}+{y}")

    # Add buttons
    tk.Button(app, text="Add Password", command=add_entry).pack(pady=5)
    tk.Button(app, text="View Passwords", command=view_entries).pack(pady=5)
    tk.Button(app, text="Search Password", command=search_entry).pack(pady=5)

    app.mainloop()


# --- CLI Logic ---
def main():
    """Main function to handle CLI commands."""
    parser = argparse.ArgumentParser(description="Password Manager")
    parser.add_argument("--add", action="store_true", help="Add a new password")
    parser.add_argument("--view", action="store_true", help="View all stored passwords")
    parser.add_argument("--delete", type=str, metavar="SERVICE", help="Delete password for a service")
    parser.add_argument("--generate", type=int, metavar="LENGTH", help="Generate a random password")
    parser.add_argument("--backup", action="store_true", help="Backup the password database")
    parser.add_argument("--restore", action="store_true", help="Restore the password database from a backup")
    parser.add_argument("--strength", type=str, metavar="PASSWORD", help="Check the strength of a password")
    parser.add_argument("--search", type=str, metavar="SERVICE", help="Search for a password by service name")
    parser.add_argument("--gui", action="store_true", help="Launch the GUI version of the password manager")

    args = parser.parse_args()

    key = load_key()
    init_db()

    if not verify_master_password():
        return

    if args.add:
        service = input("Enter service name: ").strip()
        username = input("Enter username: ").strip()
        password = getpass("Enter password: ").strip()
        add_password(service, username, password, key)
        print(f"Password for {service} added successfully!")

    elif args.view:
        passwords = get_passwords(key)
        if not passwords:
            print("No passwords found.")
        else:
            for service, username, password in passwords:
                print(f"Service: {service}, Username: {username}, Password: {password}")

    elif args.delete:
        delete_password(args.delete)
        print(f"Password for {args.delete} deleted successfully!")

    elif args.generate:
        print("Generated password:", generate_password(args.generate))

    elif args.backup:
        backup_database()

    elif args.restore:
        restore_database()

    elif args.strength:
        strength = check_password_strength(args.strength)
        print(f"Password strength: {strength}")

    elif args.search:
        results = search_password(args.search, key)
        if not results:
            print("No matching passwords found.")
        else:
            for service, username, password in results:
                print(f"Service: {service}, Username: {username}, Password: {password}")

    elif args.gui:
        launch_gui()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

