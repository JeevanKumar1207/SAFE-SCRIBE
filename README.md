# SAFE-SCRIBE
A Secure Offline GUI Password Manager for **Linux** built with Python and Tkinter.

---

## 🛡️ Features
- ✅ **Secure AES Encryption** for stored credentials.
- ✅ **Offline** password manager – no internet required.
- ✅ **Live suggestions** for services and usernames.
- ✅ **Password generator** with custom criteria.
- ✅ **Clipboard copy**, **view toggle**, and **keyboard navigation** support.
- ✅ **Multiple usernames per service**.
- ✅ **Built-in password editing and retrieval** system.
- ✅ **Auto-complete with manual dropdown** interaction.

---

## ⚠️ OS Compatibility

> ❗ This application is **only supported on Linux systems**.  
It uses system-specific features and file paths tested exclusively on **Linux (Debian/Kali/Ubuntu)**.  

Windows/Mac are not currently supported.

---

## 🧰 Requirements

Install the required Python modules:

```bash
pip install pyperclip cryptography
```

Also ensure tkinter is installed:

```bash
sudo apt install python3-tk
```

---

## 🚀 How to Run
Clone the repository and run the script:

```bash
git clone https://github.com/jeevankumar1207/SAFE-SCRIBE.git
```
```bash
cd SAFE-SCRIBE
```
```bash
python3 SAFE-SCRIBE.py
```

---

## 🔒 How It Works
- Passwords are encrypted with a user-supplied encryption key.
- Stored data is saved in passwords.enc using AES encryption.
- Temporary decrypted file (/tmp/passwords.tmp) is auto-deleted on exit.

---

## 📎 Notes
- Do not lose your encryption key – without it, your passwords are unrecoverable.
- Project does not use any online/cloud storage.
- Compatible with Python 3.10+ on Linux.
