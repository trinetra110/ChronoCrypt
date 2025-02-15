# **ChronoCrypt: Time-Locked Secure Notes with Self-Destruct** 🔐⏳

<img src="https://readme-typing-svg.herokuapp.com?color=45ffaa&size=40&width=900&height=80&lines=Welcome-to-ChronoCrypt"/>

**ChronoCrypt** is a powerful CLI-based encryption tool that allows users to create **time-locked secure notes** that self-destruct after a specified duration. It uses **AES-256 encryption (CBC mode)** to securely store sensitive information, ensuring that notes are unreadable beyond their expiry time.

🔹 **AES-256 Encryption for Maximum Security**  
🔹 **Self-Destructing Notes After Expiry**  
🔹 **User-Friendly Command-Line Interface**  
🔹 **Supports Expiry Times in Minutes, Hours, or Days**  

## 🚀 Features  
✅ **AES-256 Encryption**: Strong encryption using SHA-256 derived keys.  
✅ **Time-Locked Access**: Notes can only be read before expiry.  
✅ **Automatic Secure Deletion**: Notes are irreversibly deleted after expiry.  
✅ **User-Friendly CLI**: Simple commands for encryption & decryption.  
✅ **Supports Expiry Formats**: Set time in minutes (m), hours (h), or days (d).  

## 🛠️ Tech Stack  
| **Technology**  | **Description**              |
|---------------|--------------------------|
| **🐍 Python**  | Programming Language       |
| **🔐 PyCryptodome**  | AES-256 Encryption Library   |
| **📂 OS**      | File Handling & Secure Deletion    |

## 📌 Prerequisites  

- **Python 3.x** (Download: [Python.org](https://www.python.org/downloads/))  

## ⚡ Installation & Usage  

### **1️⃣ Clone the Repository**  
```bash
git clone https://github.com/trinetra110/ChronoCrypt.git
cd ChronoCrypt  
```

### **2️⃣ Install Dependencies**  
```bash
pip install -r requirements.txt  
```

### **3️⃣ Encrypt a Secure Note**  
```bash
python main.py encrypt "Your Secret Message" "YourPassword" -t 30m -f my_secret.sec  
```
- **Your Secret Message** → The message to encrypt  
- **YourPassword** → The password for encryption/decryption  
- **-t 30m** → (Optional) The note will self-destruct in 30 minutes (supports `m`, `h`, `d`) (default: 1h).  
- **-f my_secret.sec** → (Optional) Save the note to a custom file (binary like .sec) (default: sec_note.sec).  

### **4️⃣ Decrypt & Read a Note (Before Expiry)**  
```bash
python main.py decrypt my_secret.sec "YourPassword"  
```
- If the note is **not expired**, the decrypted message will be displayed.  
- If the note **is expired**, it will be securely deleted automatically.  

## 🎯 How It Works  
1️⃣ **Encryption**:  
   - The message is encrypted using **AES-256 (CBC mode)**.  
   - A time-lock mechanism ensures notes are valid only until expiry.  
   - The encrypted note is saved in a `.sec` file.  

2️⃣ **Decryption & Expiry Check**:  
   - When attempting to decrypt, the expiry timestamp is checked.  
   - If **not expired**, the message is decrypted and displayed.  
   - If **expired**, the note is securely deleted to prevent access.  

3️⃣ **Secure Deletion**:  
   - The file is **overwritten with random bytes** before deletion.  
   - This prevents forensic recovery of the note.  

## 🏆 Why Use ChronoCrypt?  
🔹 **Store Temporary Secrets**: Ideal for one-time secure message sharing.  
🔹 **Automated Data Expiry**: No need to manually delete expired notes.  
🔹 **Lightweight & Fast**: CLI-based tool, no additional setup required.  
🔹 **Bulletproof Security**: AES-256 encryption with automatic secure deletion.  

## 📜 License  
This project is licensed under the **MIT License**.  

