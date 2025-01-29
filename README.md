# Password Manager

## Description
The **Password Manager** is a Python application designed to securely store and manage your passwords. It features strong encryption using the `cryptography` library and provides both a Command-Line Interface (CLI) and a Graphical User Interface (GUI) for user convenience. The tool also includes advanced features like password generation, password strength checking, search functionality, and database backup and restore.

---

## Features
- **Master Password Authentication**: Protects access to stored passwords.
- **Secure Password Storage**: Uses AES encryption to safely store passwords.
- **Backup and Restore**: Easily back up and restore the database.
- **Password Strength Checker**: Rates the strength of passwords.
- **Search Functionality**: Quickly find passwords by service name.
- **GUI Integration**: A user-friendly graphical interface built with `tkinter`.
- **Random Password Generator**: Generate secure, random passwords.

---

## Installation
### Prerequisites
1. Python 3.7 or higher installed on your system.
2. Install the `cryptography` library:
   ```bash
   pip install cryptography
   ```

### Cloning the Repository
1. Clone this repository:
   ```bash
   git clone https://github.com/jjsetech/password_manager.git
   ```
2. Navigate to the project directory:
   ```bash
   cd password_manager
   ```

---

## Usage
The Password Manager can be used through CLI commands or via the GUI.

### Command-Line Interface (CLI)
Run the application using the command line. Below are the available commands:

#### 1. **Add a New Password**
Add a new service, username, and password:
```bash
python password_manager.py --add
```
**Example:**
```
Enter service name: Gmail
Enter username: user@gmail.com
Enter password: [hidden]
Password for Gmail added successfully!
```

#### 2. **View All Stored Passwords**
Retrieve and view all stored passwords:
```bash
python password_manager.py --view
```
**Example Output:**
```
Service: Gmail, Username: user@gmail.com, Password: my_secure_password
Service: Facebook, Username: user123, Password: another_password
```

#### 3. **Delete a Password**
Delete a password for a specific service:
```bash
python password_manager.py --delete Gmail
```
**Example Output:**
```
Password for Gmail deleted successfully!
```

#### 4. **Generate a Secure Password**
Generate a random password of a specified length:
```bash
python password_manager.py --generate 16
```
**Example Output:**
```
Generated password: X3z@p!T5k#1yV$W9
```

#### 5. **Check Password Strength**
Check the strength of a given password:
```bash
python password_manager.py --strength "MyPassw0rd!"
```
**Example Output:**
```
Password strength: Strong
```

#### 6. **Search for a Password**
Search for a password by service name:
```bash
python password_manager.py --search Gmail
```
**Example Output:**
```
Service: Gmail, Username: user@gmail.com, Password: my_secure_password
```

#### 7. **Backup the Database**
Create a backup of the database:
```bash
python password_manager.py --backup
```
**Example Output:**
```
Backup created: passwords.db.backup
```

#### 8. **Restore the Database**
Restore the database from a backup file:
```bash
python password_manager.py --restore
```
**Example Output:**
```
Database restored from backup.
```

#### 9. **Launch the GUI**
Launch the graphical user interface:
```bash
python password_manager.py --gui
```

---

## Graphical User Interface (GUI)
The GUI provides an easy-to-use interface for managing your passwords.

### Features:
- **Add Password**: Enter service, username, and password.
- **View Passwords**: Display all stored passwords.
- **Search Password**: Find passwords by service name.

To use the GUI, simply run:
```bash
python password_manager.py --gui
```

---

## Security Considerations
1. **Master Password**: Ensure your master password is strong and kept private.
2. **Database File**: The database (`passwords.db`) is encrypted, but keep it in a secure location.
3. **Backup Files**: Store backups securely as they contain encrypted password data.

---

## Contribution
Contributions are welcome! Feel free to open issues or submit pull requests for improvements or new features.

1. Fork the repository.
2. Create a new branch for your feature:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add feature-name"
   ```
4. Push your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Author
[Jeronimo Junior](https://github.com/jjsetech)

