# Secure-File-Encryption-Decryption-Tool-GUI-
Secure File Encryption &amp; Decryption Tool is a Python-based GUI application that securely encrypts and decrypts files using AES-256-GCM with PBKDF2 key derivation. It includes a live password-strength meter, file browsing, progress bar, error handling, and responsive interface, ensuring professional file protection against unauthorized access.

Install Required Packages
Your app requires cryptography and customtkinter (for modern GUI).

Run:
pip install cryptography customtkinter
Run the Application

In terminal (inside project folder and virtual environment):
python mainapp.py
The GUI window should open with Encrypt / Decrypt / Settings / About sidebar.

Test:
Click Encrypt File
Browse a file
Enter a strong password (watch the live strength bar)
Click Encrypt → It will create a .enc file.

To decrypt:
Click Decrypt File
Browse the .enc file
Enter the same password
Click Decrypt → original file restored.
