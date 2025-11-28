# Advanced-Encryption-Tool

Company: Codtech IT Solutions<br>
Name: Chandra Sekhar Ghosh<br>
Intern ID: CT04DR1779<br>
Domain: Cyber Security & Ethical Hacking<br>
Duration: 4 weeks<br>
Mentor: Muzammil<br>

A professional-grade command-line tool for encrypting and decrypting files using military-grade AES-256-GCM encryption with authenticated encryption and password-based key derivation.

---

## ✨ Features

- **🔒 Military-Grade Encryption**: AES-256-GCM authenticated encryption
- **🛡️ Tamper Detection**: Automatically detects if files have been modified
- **🔑 Strong Key Derivation**: PBKDF2-HMAC-SHA256 with 200,000 iterations
- **🎲 Cryptographically Secure**: Random salt and nonce for every encryption
- **📦 Self-Contained**: Complete file format with metadata
- **💻 Cross-Platform**: Works on Windows, macOS, and Linux
- **🚀 Fast & Efficient**: Optimized for large files
- **🧹 Memory Safe**: Sensitive data is cleared from memory after use
- **📝 User-Friendly CLI**: Simple, intuitive command-line interface
- **⚠️ Safe Defaults**: Prevents accidental file overwrites

---

## 🔐 Security Details

### Encryption Algorithm
- **Algorithm**: AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes) - recommended size for GCM
- **Authentication Tag**: 128 bits (16 bytes) - prevents tampering

### Key Derivation
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 200,000 (protection against brute-force attacks)
- **Salt Size**: 128 bits (16 bytes) - unique per encryption
- **Output**: 256-bit AES key

### Why AES-GCM?
AES-GCM provides **authenticated encryption**, which means:
- ✅ **Confidentiality**: Data is encrypted and unreadable without the key
- ✅ **Integrity**: Any tampering with the encrypted file is detected
- ✅ **Authenticity**: Verifies the data came from the expected source

---

## 📥 Installation

### Prerequisites
- **Python 3.7 or higher**
- **pip** (Python package manager)

### Step 1: Install Python
If you don't have Python installed:

**Windows:**
1. Download from [python.org](https://www.python.org/downloads/)
2. Run installer and check "Add Python to PATH"

**macOS:**
```bash
brew install python3
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3 python3-pip
```

### Step 2: Install Dependencies
```bash
pip install cryptography
```

Or using requirements.txt:
```bash
pip install -r requirements.txt
```

### Step 3: Download SecureCrypt
**Option A: Clone Repository**
```bash
git clone https://github.com/ChandraSekharGhosh/advanced-encryption-tool.git

git@github.com:ChandraSekharGhosh/advanced-encryption-tool.git

gh repo clone ChandraSekharGhosh/advanced-encryption-tool
```

**Option B: Download ZIP**
1. Download the ZIP file from the repository
2. Extract to your desired location
3. Navigate to the folder in terminal/command prompt

### Step 4: Make Executable (Optional - Linux/macOS)
```bash
chmod +x securecrypt.py
```

---

## 🚀 Quick Start

### Encrypt a File
```bash
python securecrypt.py encrypt -i myfile.pdf -o myfile.pdf.enc
```
You'll be prompted to enter and confirm a password.

### Decrypt a File
```bash
python securecrypt.py decrypt -i myfile.pdf.enc -o myfile_decrypted.pdf
```
You'll be prompted to enter the password.

---

## 📖 Usage

### General Syntax
```bash
python securecrypt.py [command] [options]
```

### Commands

#### 1. Encrypt Command
```bash
python securecrypt.py encrypt -i INPUT_FILE -o OUTPUT_FILE [OPTIONS]
```

**Options:**
- `-i, --input`: Path to the file you want to encrypt (required)
- `-o, --output`: Path where encrypted file will be saved (required)
- `-p, --password`: Password to use (optional, will prompt if not provided)
- `--overwrite`: Allow overwriting existing output file

**Example:**
```bash
python securecrypt.py encrypt -i document.docx -o document.docx.enc
```

#### 2. Decrypt Command
```bash
python securecrypt.py decrypt -i INPUT_FILE -o OUTPUT_FILE [OPTIONS]
```

**Options:**
- `-i, --input`: Path to the encrypted file (required)
- `-o, --output`: Path where decrypted file will be saved (required)
- `-p, --password`: Password to use (optional, will prompt if not provided)
- `--overwrite`: Allow overwriting existing output file

**Example:**
```bash
python securecrypt.py decrypt -i document.docx.enc -o document_restored.docx
```

### Help Command
```bash
python securecrypt.py --help
python securecrypt.py encrypt --help
python securecrypt.py decrypt --help
```

---

## 💡 Examples

### Example 1: Encrypt a Document
```bash
# Encrypt with password prompt (recommended)
python securecrypt.py encrypt -i contract.pdf -o contract.pdf.encrypted

# Output:
# Enter password: ********
# Confirm password: ********
# [+] Encrypting:   contract.pdf
# [+] Output file:  contract.pdf.encrypted
# [+] File size:    1.25 MB
# [+] Encryption successful.
# [*] Keep your password safe. Without it, decryption is impossible.
```

### Example 2: Decrypt a Document
```bash
python securecrypt.py decrypt -i contract.pdf.encrypted -o contract_restored.pdf

# Output:
# Enter password: ********
# [+] Decrypting:   contract.pdf.encrypted
# [+] Output file:  contract_restored.pdf
# [+] Decryption successful.
# [+] Output size: 1.25 MB
```

### Example 3: Encrypt Multiple Files (Batch Script)
**Windows (batch.bat):**
```batch
@echo off
for %%f in (*.txt) do (
    python securecrypt.py encrypt -i "%%f" -o "%%f.enc" -p MySecretPassword123
)
```

**Linux/macOS (batch.sh):**
```bash
#!/bin/bash
for file in *.txt; do
    python securecrypt.py encrypt -i "$file" -o "$file.enc" -p MySecretPassword123
done
```

### Example 4: Encrypt with Password on Command Line
```bash
# WARNING: Password visible in shell history!
python securecrypt.py encrypt -i sensitive.doc -o sensitive.doc.enc -p "MyPassword123"
```

### Example 5: Overwrite Existing File
```bash
python securecrypt.py decrypt -i data.enc -o data.txt --overwrite
```

---

## 📦 File Format

SecureCrypt uses a custom file format with the following structure:

```
┌─────────────────────────────────────────────┐
│  HEADER                                     │
├─────────────────────────────────────────────┤
│  Magic Bytes (8 bytes): "AES256FT"          │
│  Version (1 byte): 1                        │
│  Salt Length (1 byte)                       │
│  Nonce Length (1 byte)                      │
│  Iterations (4 bytes, big-endian)           │
│  Salt (16 bytes)                            │
│  Nonce (12 bytes)                           │
├─────────────────────────────────────────────┤
│  ENCRYPTED DATA                             │
├─────────────────────────────────────────────┤
│  Ciphertext + Authentication Tag            │
└─────────────────────────────────────────────┘
```

**Header Details:**
- **Magic Bytes**: Identifies file as SecureCrypt format
- **Version**: Format version (currently 1)
- **Salt**: Random salt used for key derivation
- **Nonce**: Random nonce used for GCM encryption
- **Iterations**: Number of PBKDF2 iterations used

---

## 🛡️ Security Best Practices

### Password Guidelines
✅ **DO:**
- Use passwords with **at least 16 characters**
- Include uppercase, lowercase, numbers, and symbols
- Use a unique password for each file
- Consider using a password manager
- Use passphrases: "correct-horse-battery-staple-2024!"

❌ **DON'T:**
- Use common words or phrases
- Reuse passwords from other services
- Use personal information (birthdays, names)
- Share passwords via insecure channels
- Write passwords down in plain text

### Example Strong Passwords
```
Good: Tr0pic@l-Mango$2024-Sunshine!
Better: correct-horse-battery-staple-renewable-energy
Best: Use a password manager to generate 20+ character random passwords
```

### Storage Recommendations
1. **Encrypted Files**: Store in secure, backed-up locations
2. **Passwords**: Use a password manager like Bitwarden, 1Password, or KeePass
3. **Backups**: Keep encrypted backups in multiple locations
4. **Original Files**: Securely delete after encryption (use `shred` on Linux)

### What If You Forget Your Password?
⚠️ **WARNING**: If you forget your password, **your data is permanently lost**. There is no "password recovery" mechanism. This is by design - it's what makes the encryption secure.

**Recommendations:**
- Test decryption immediately after encryption
- Store password in a secure password manager
- Consider storing a password hint (NOT the password) separately

---

## ❓ FAQ

### Q: How secure is SecureCrypt?
**A:** Very secure. It uses AES-256-GCM, the same encryption standard used by:
- Military and government agencies
- Banking institutions
- Secure messaging apps (Signal, WhatsApp)
- Cloud storage providers

### Q: Can the encrypted files be cracked?
**A:** With a strong password (16+ characters), it would take billions of years to crack using current technology. However, weak passwords can be cracked quickly.

### Q: What file types can I encrypt?
**A:** Any file type - documents, images, videos, archives, databases, etc.

### Q: Does encryption change file size?
**A:** Encrypted files are slightly larger (~50 bytes) due to the header and authentication tag.

### Q: Can I encrypt folders?
**A:** Not directly. You can:
1. Compress the folder to a ZIP file
2. Encrypt the ZIP file
```bash
# Create archive
zip -r myfolder.zip myfolder/
# Encrypt archive
python securecrypt.py encrypt -i myfolder.zip -o myfolder.zip.enc
```

### Q: Is it safe to store encrypted files in the cloud?
**A:** Yes! That's the whole point. The files are encrypted locally before upload, so cloud providers cannot read them.

### Q: Can I use this for sensitive business data?
**A:** Yes, as long as you follow security best practices. Many organizations use AES-256 for data protection.

### Q: Does this work offline?
**A:** Yes, completely offline. No internet connection required.

### Q: What happens if the file is corrupted?
**A:** GCM mode will detect any corruption or tampering and refuse to decrypt.

---

## 🔧 Troubleshooting

### Problem: "Module 'cryptography' not found"
**Solution:**
```bash
pip install cryptography
# or
pip3 install cryptography
```

### Problem: "Permission denied"
**Solution (Linux/macOS):**
```bash
chmod +x securecrypt.py
# or run with python explicitly
python securecrypt.py encrypt -i file.txt -o file.enc
```

### Problem: "Decryption failed. Wrong password or corrupted file."
**Causes:**
1. Wrong password (most common)
2. File was modified after encryption
3. File transfer corrupted the data
4. Wrong file (not a SecureCrypt encrypted file)

**Solutions:**
- Double-check your password (check Caps Lock)
- Try re-downloading the file
- Verify file integrity with checksum

### Problem: "Output file already exists"
**Solution:**
```bash
# Add --overwrite flag
python securecrypt.py decrypt -i file.enc -o file.txt --overwrite
```

### Problem: "File too large / Memory error"
**Solution:**
- Ensure you have enough RAM (file is loaded into memory)
- For very large files (>1GB), split them first:
```bash
# Linux/macOS
split -b 500M largefile.zip chunk_
# Encrypt each chunk separately
```

### Problem: Python not recognized (Windows)
**Solution:**
1. Reinstall Python with "Add to PATH" checked
2. Or use full path: `C:\Python39\python.exe securecrypt.py ...`

---

### Development Setup
```bash
git clone https://github.com/yourusername/securecrypt.git
cd securecrypt
pip install -r requirements-dev.txt
```

### Running Tests
```bash
python -m pytest tests/
```

---

## ⚠️ Disclaimer

This software is provided "as is", without warranty of any kind. While SecureCrypt uses industry-standard encryption algorithms, the authors are not responsible for any data loss. Always keep backups of important files.

**Remember**: 
- Test decryption before deleting original files
- Store passwords securely
- Keep backups in multiple locations
- No password = No recovery

---

## 🌟 Acknowledgments

- Built with [cryptography](https://cryptography.io/) library
- AES-GCM algorithm from NIST standards
- Inspired by modern encryption best practices

---

## 🔗 Useful Links

- [Cryptography Library Documentation](https://cryptography.io/)
- [NIST AES-GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Password Security Best Practices](https://www.nist.gov/password-guidelines)

---

<p align="center">
  Made with ❤️ for secure file encryption
</p>

<p align="center">
  <strong>⭐ Star this repository if you find it useful!</strong>
</p>
