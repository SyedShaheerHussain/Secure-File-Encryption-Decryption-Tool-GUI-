import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ================= CONFIG =================
ITERATIONS = 200_000
KEY_LENGTH = 32
BACKEND = default_backend()

# ================= CRYPTO =================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        data = f.read()

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aes = AESGCM(key)

    encrypted = aes.encrypt(nonce, data, None)
    out = file_path + ".enc"

    with open(out, "wb") as f:
        f.write(salt + nonce + encrypted)

    return out

def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        raw = f.read()

    salt, nonce, cipher = raw[:16], raw[16:28], raw[28:]
    key = derive_key(password, salt)
    aes = AESGCM(key)

    data = aes.decrypt(nonce, cipher, None)
    out = file_path.replace(".enc", "")

    with open(out, "wb") as f:
        f.write(data)

    return out

# ================= PASSWORD METER (REAL FIX) =================
def password_meter(password: str):
    length_score = min(len(password) / 16, 1.0)

    variety = 0
    if any(c.islower() for c in password): variety += 1
    if any(c.isupper() for c in password): variety += 1
    if any(c.isdigit() for c in password): variety += 1
    if any(c in "!@#$%^&*()_+-=" for c in password): variety += 1

    variety_score = variety / 4
    value = min((length_score * 0.6) + (variety_score * 0.4), 1.0)

    if value < 0.3:
        return "Weak", "red", value
    elif value < 0.55:
        return "Medium", "yellow", value
    elif value < 0.8:
        return "Strong", "orange", value
    else:
        return "Very Strong", "green", value

# ================= GUI =================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SecureApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Encryption Tool")
        self.geometry("1000x600")

        self.sidebar = ctk.CTkFrame(self, width=200)
        self.sidebar.pack(side="left", fill="y")

        self.container = ctk.CTkFrame(self)
        self.container.pack(side="right", expand=True, fill="both")

        self.create_sidebar()
        self.show_encrypt()

    def create_sidebar(self):
        for text, cmd in [
            ("Encrypt File", self.show_encrypt),
            ("Decrypt File", self.show_decrypt),
            ("Settings", self.show_settings),
            ("About", self.show_about),
        ]:
            ctk.CTkButton(self.sidebar, text=text, command=cmd).pack(
                pady=8, padx=10, fill="x"
            )

    def clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    # ================= PASSWORD UI (FIXED) =================
    def password_ui(self, parent):
        pwd = ctk.CTkEntry(parent, show="*", width=300)
        pwd.pack(pady=6)

        show = ctk.BooleanVar()
        ctk.CTkCheckBox(
            parent,
            text="Show Password 👁️",
            variable=show,
            command=lambda: pwd.configure(show="" if show.get() else "*")
        ).pack()

        label = ctk.CTkLabel(parent, text="Password Strength:")
        label.pack(pady=(8, 2))

        bar = ctk.CTkProgressBar(parent, width=320)
        bar.pack(pady=4)
        bar.set(0)

        def update(event=None):
            strength, color, value = password_meter(pwd.get())
            label.configure(text=f"Password Strength: {strength}", text_color=color)
            bar.set(value)

        pwd.bind("<KeyRelease>", update)
        return pwd

    # ================= ENCRYPT =================
    def show_encrypt(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        f.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(f, text="Encrypt File", font=("Arial", 24)).pack(pady=10)

        file_entry = ctk.CTkEntry(f, width=420)
        file_entry.pack(pady=5)
        ctk.CTkButton(
            f,
            text="Browse File",
            command=lambda: file_entry.insert(0, filedialog.askopenfilename())
        ).pack()

        password_entry = self.password_ui(f)

        def start():
            strength, _, _ = password_meter(password_entry.get())
            if strength in ["Weak", "Medium"]:
                messagebox.showwarning("Weak Password", "Use Strong or Very Strong password")
                return

            def task():
                try:
                    out = encrypt_file(file_entry.get(), password_entry.get())
                    messagebox.showinfo("Success", f"Encrypted:\n{out}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

            threading.Thread(target=task).start()

        ctk.CTkButton(f, text="Encrypt", command=start).pack(pady=15)

    # ================= DECRYPT =================
    def show_decrypt(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        f.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(f, text="Decrypt File", font=("Arial", 24)).pack(pady=10)

        file_entry = ctk.CTkEntry(f, width=420)
        file_entry.pack(pady=5)
        ctk.CTkButton(
            f,
            text="Browse Encrypted File",
            command=lambda: file_entry.insert(
                0, filedialog.askopenfilename(filetypes=[("ENC", "*.enc")])
            )
        ).pack()

        password_entry = self.password_ui(f)

        def start():
            try:
                out = decrypt_file(file_entry.get(), password_entry.get())
                messagebox.showinfo("Success", f"Decrypted:\n{out}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(f, text="Decrypt", command=start).pack(pady=15)

    def show_settings(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        f.pack(expand=True, fill="both")
        ctk.CTkButton(
            f,
            text="Toggle Dark / Light Mode",
            command=lambda: ctk.set_appearance_mode(
                "Light" if ctk.get_appearance_mode() == "Dark" else "Dark"
            )
        ).pack(pady=40)

    def show_about(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        f.pack(expand=True, fill="both")
        ctk.CTkLabel(
            f,
            text="Secure File Encryption Tool\nAES-256-GCM\nPBKDF2\nProfessional Password Meter",
            font=("Arial", 16),
            justify="center"
        ).pack(expand=True)

# ================= RUN =================
if __name__ == "__main__":
    SecureApp().mainloop()
