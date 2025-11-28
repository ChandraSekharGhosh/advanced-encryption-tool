import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

class AdvancedEncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced AES-256 Encryption Tool")
        self.root.geometry("700x550")
        self.root.resizable(False, False)
        
        # Color scheme
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        self.button_color = "#313244"
        self.success_color = "#a6e3a1"
        self.error_color = "#f38ba8"
        
        self.root.configure(bg=self.bg_color)
        
        self.selected_file = None
        self.setup_ui()
    
    def setup_ui(self):
        # Title
        title = tk.Label(
            self.root,
            text="🔐 Advanced AES-256 Encryption Tool",
            font=("Helvetica", 20, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack(pady=20)
        
        # File Selection Frame
        file_frame = tk.Frame(self.root, bg=self.bg_color)
        file_frame.pack(pady=10, padx=30, fill="x")
        
        tk.Label(
            file_frame,
            text="Selected File:",
            font=("Helvetica", 11),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor="w")
        
        self.file_label = tk.Label(
            file_frame,
            text="No file selected",
            font=("Helvetica", 10),
            bg=self.button_color,
            fg=self.fg_color,
            wraplength=600,
            justify="left",
            padx=10,
            pady=8
        )
        self.file_label.pack(fill="x", pady=5)
        
        browse_btn = tk.Button(
            file_frame,
            text="📁 Browse File",
            command=self.browse_file,
            font=("Helvetica", 11, "bold"),
            bg=self.button_color,
            fg=self.fg_color,
            activebackground=self.accent_color,
            cursor="hand2",
            relief="flat",
            padx=20,
            pady=8
        )
        browse_btn.pack(pady=5)
        
        # Password Frame
        password_frame = tk.Frame(self.root, bg=self.bg_color)
        password_frame.pack(pady=15, padx=30, fill="x")
        
        tk.Label(
            password_frame,
            text="Encryption Password:",
            font=("Helvetica", 11),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor="w")
        
        self.password_entry = tk.Entry(
            password_frame,
            show="*",
            font=("Helvetica", 12),
            bg=self.button_color,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            relief="flat",
            width=40
        )
        self.password_entry.pack(fill="x", pady=5, ipady=8)
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_pass_check = tk.Checkbutton(
            password_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password,
            font=("Helvetica", 9),
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.accent_color
        )
        show_pass_check.pack(anchor="w", pady=2)
        
        # Buttons Frame
        buttons_frame = tk.Frame(self.root, bg=self.bg_color)
        buttons_frame.pack(pady=20)
        
        encrypt_btn = tk.Button(
            buttons_frame,
            text="🔒 Encrypt File",
            command=self.encrypt_file,
            font=("Helvetica", 12, "bold"),
            bg=self.success_color,
            fg="#1e1e2e",
            activebackground="#a6e3a1",
            cursor="hand2",
            relief="flat",
            padx=30,
            pady=12,
            width=15
        )
        encrypt_btn.grid(row=0, column=0, padx=10)
        
        decrypt_btn = tk.Button(
            buttons_frame,
            text="🔓 Decrypt File",
            command=self.decrypt_file,
            font=("Helvetica", 12, "bold"),
            bg=self.accent_color,
            fg="#1e1e2e",
            activebackground="#89b4fa",
            cursor="hand2",
            relief="flat",
            padx=30,
            pady=12,
            width=15
        )
        decrypt_btn.grid(row=0, column=1, padx=10)
        
        # Progress Bar
        self.progress = ttk.Progressbar(
            self.root,
            orient="horizontal",
            length=600,
            mode="indeterminate"
        )
        self.progress.pack(pady=15)
        
        # Status Label
        self.status_label = tk.Label(
            self.root,
            text="Ready",
            font=("Helvetica", 10),
            bg=self.bg_color,
            fg=self.fg_color
        )
        self.status_label.pack(pady=5)
        
        # Info Frame
        info_frame = tk.Frame(self.root, bg=self.button_color)
        info_frame.pack(pady=15, padx=30, fill="x")
        
        info_text = """ℹ️ Security Information:
• Uses AES-256 encryption (military-grade security)
• PBKDF2 key derivation with 100,000 iterations
• Unique salt and IV for each encryption
• Encrypted files have .encrypted extension"""
        
        tk.Label(
            info_frame,
            text=info_text,
            font=("Helvetica", 9),
            bg=self.button_color,
            fg=self.fg_color,
            justify="left",
            padx=15,
            pady=10
        ).pack()
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select a file to encrypt/decrypt",
            filetypes=[("All Files", "*.*")]
        )
        if filename:
            self.selected_file = filename
            self.file_label.config(text=filename)
            self.status_label.config(text="File selected successfully", fg=self.success_color)
    
    def toggle_password(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def derive_key(self, password, salt):
        """Derive a 256-bit key from password using PBKDF2"""
        kdf = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # 100,000 iterations
        )
        return kdf
    
    def encrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return
        
        if len(password) < 8:
            messagebox.showwarning("Weak Password", "Password should be at least 8 characters long!")
            return
        
        try:
            self.progress.start()
            self.status_label.config(text="Encrypting...", fg=self.accent_color)
            self.root.update()
            
            # Read file
            with open(self.selected_file, 'rb') as f:
                plaintext = f.read()
            
            # Generate random salt and IV
            salt = secrets.token_bytes(16)
            iv = secrets.token_bytes(16)
            
            # Derive key
            key = self.derive_key(password, salt)
            
            # Pad plaintext
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            # Encrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Save encrypted file with salt and IV
            output_file = self.selected_file + '.encrypted'
            with open(output_file, 'wb') as f:
                f.write(salt)
                f.write(iv)
                f.write(ciphertext)
            
            self.progress.stop()
            self.status_label.config(text="Encryption successful!", fg=self.success_color)
            messagebox.showinfo(
                "Success",
                f"File encrypted successfully!\n\nSaved as:\n{output_file}\n\n⚠️ Keep your password safe!"
            )
            
        except Exception as e:
            self.progress.stop()
            self.status_label.config(text="Encryption failed!", fg=self.error_color)
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")
    
    def decrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        if not self.selected_file.endswith('.encrypted'):
            response = messagebox.askyesno(
                "Warning",
                "This file doesn't have .encrypted extension.\nContinue anyway?"
            )
            if not response:
                return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return
        
        try:
            self.progress.start()
            self.status_label.config(text="Decrypting...", fg=self.accent_color)
            self.root.update()
            
            # Read encrypted file
            with open(self.selected_file, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                ciphertext = f.read()
            
            # Derive key
            key = self.derive_key(password, salt)
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Save decrypted file
            output_file = self.selected_file.replace('.encrypted', '.decrypted')
            if output_file == self.selected_file:
                output_file = self.selected_file + '.decrypted'
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            self.progress.stop()
            self.status_label.config(text="Decryption successful!", fg=self.success_color)
            messagebox.showinfo(
                "Success",
                f"File decrypted successfully!\n\nSaved as:\n{output_file}"
            )
            
        except Exception as e:
            self.progress.stop()
            self.status_label.config(text="Decryption failed!", fg=self.error_color)
            messagebox.showerror(
                "Error",
                f"Decryption failed!\n\nPossible reasons:\n• Wrong password\n• Corrupted file\n• Not an encrypted file\n\nError: {str(e)}"
            )

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedEncryptionTool(root)
    root.mainloop()