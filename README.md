# 🔐 Secure File Encryption & Decryption Tool

Secure File Encryption & Decryption Tool is a Python-based desktop application that allows users to securely encrypt and decrypt files using modern cryptographic standards. The application uses **AES-256-GCM** for encryption along with **PBKDF2 (SHA-256)** for secure password-based key derivation, ensuring strong protection against unauthorized access. A modern, responsive GUI is provided using **CustomTkinter**.


## 📌 Features

- AES-256-GCM authenticated encryption
- Secure password-based key derivation using PBKDF2 + SHA-256
- Live password strength meter with real-time progress bar
- File encryption and decryption with `.enc` extension
- Secure random salt and nonce generation for each file
- Modern, responsive GUI with Dark/Light mode
- Show/Hide password toggle
- Multi-threaded operations to keep UI responsive
- Proper error handling and user-friendly alerts
- Cross-platform support (Windows, macOS, Linux)

## 🛠️ Technologies Used

- Python 3.10+
- CustomTkinter (GUI Framework)
- Cryptography Library
- AES-256-GCM (Symmetric Encryption)
- PBKDF2 (Password-Based Key Derivation)
- SHA-256 Hashing
- Tkinter File Dialogs
- Multi-threading

## ⚙️ Installation Guide

### 1️⃣ Install Python

Check if Python is installed:
```
python --version

```
If not installed, download and install Python 3.10+ from:
[Python](https://www.python.org/downloads/)

*⚠️ Important: During installation, check "Add Python to PATH"*

### 2️⃣ Clone or Download the Project
```
git clone https://github.com/SyedShaheerHussain/Secure-File-Encryption-Decryption-Tool-GUI-.git

```
```
cd Secure File Encryption & Decryption Tool

```
Or manually download and extract the project folder.

### 3️⃣ (Optional) Create a Virtual Environment
```
python -m venv venv

```
*Activate it:*

Windows
```
venv\Scripts\activate

```

macOS / Linux

```
source venv/bin/activate

```

### 4️⃣ Install Required Packages
```
pip install cryptography customtkinter

```
*Verify installation:*

```
python -c "import cryptography, customtkinter"

```
### ▶️ How to Run the Application
```
python mainapp.py

```

After running, the GUI window will open.

## 🔐 How Encryption Works

1. User selects a file using the Browse File button.

2. User enters a password.

3. Password is validated using a live password strength meter.

4. A secure encryption key is derived using PBKDF2 + SHA-256.

5. AES-256-GCM encrypts the file with a random salt and nonce.

6. Encrypted file is saved with .enc extension.

7. Success message displays encrypted file location.

## 🔓 How Decryption Works

1. User selects an encrypted .enc file.

2. User enters the same password used for encryption.

3. The encryption key is regenerated using PBKDF2.

4. AES-256-GCM decrypts the file.

5. Original file is restored if password is correct.

6. Error message is shown for incorrect passwords or corrupted files.

## 🔑 Password Strength Meter

*The application includes a real-time password strength meter based on:*

* Password length

* Uppercase characters

* Lowercase characters

* Digits

* Special symbols

* Strength Levels:

* Weak (Red)

* Medium (Yellow)

* Strong (Orange)

* Very Strong (Green)

* Weak and medium passwords are blocked during encryption.

## 🎨 GUI Overview

- Sidebar navigation (Encrypt, Decrypt, Settings, About)

- Modern buttons, spacing, and typography

- Responsive layout

- Dark / Light mode toggle

- Password visibility toggle

- Progress bars for encryption feedback

## 🧪 Security Design Highlights

* AES-256-GCM ensures confidentiality and integrity

* Random salt prevents rainbow-table attacks

* Nonce ensures unique encryption per file

* Keys are never stored on disk

* Passwords are never saved in plaintext

* Encryption logic separated from GUI logic

* Industry-standard cryptography practices followed

## 🖥️ Create Standalone Executable (Optional)

*Install PyInstaller:*

```
pip install pyinstaller

```

*Build executable:*
```
pyinstaller --onefile --windowed mainapp.py

```

The executable will be available in the dist/ folder.

## 📚 Learning Outcomes

* Understanding of symmetric encryption (AES)

* Secure password-based key derivation

* GUI development with CustomTkinter

* Secure file handling in Python

* Multi-threaded desktop applications

* Real-world cryptography implementation

* Secure software design principles

## 🚀 Future Enhancements

1. Folder encryption support

2. Secure file deletion (shredding)

3. Master password login system

4. Key rotation support

5. Hybrid encryption (AES + RSA)

6. Cloud storage integration

7. Two-factor authentication (2FA)

8. Auto-lock and retry limits

## 👨‍💻 Author

Developed by ( © Syed Shaheer Hussain)
A professional Python-based cryptography and secure software project.

## 📄 License

> [!IMPORTANT]
> This project is intended for educational and academic purposes.
> Use responsibly and follow local data protection laws.

## ⭐ Final Note

> [!Note]
> This project demonstrates practical implementation of modern encryption standards with a professional GUI. It is suitable for Final Year Projects (FYP), portfolio showcases, and learning secure software development.
