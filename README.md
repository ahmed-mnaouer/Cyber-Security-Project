# 🔐 CipherGuard

**"Secure Every Word, Protect Every Thought."**

CipherGuard is a web-based encryption and decryption tool that empowers users to secure their messages using state-of-the-art cryptographic algorithms: **AES**, **RSA**, and **ECC**. Built with a Flask backend and a clean, user-friendly frontend, CipherGuard provides hands-on understanding and functionality of modern encryption standards.

---

## 🚀 Features

- 🔒 **AES (Advanced Encryption Standard)** – Symmetric encryption with user-supplied or auto-generated keys.
- 🔐 **RSA (Rivest–Shamir–Adleman)** – Asymmetric encryption using public-private key pairs.
- 🧠 **ECC (Elliptic Curve Cryptography)** – Efficient asymmetric encryption offering secure key exchange and AES hybrid encryption.
- 🌐 **Web Interface** – Built using HTML, CSS, and JavaScript.
- 🔄 **Two-Way Operations** – Support for both **Encryption** and **Decryption** with key inputs.

---

## 🛠️ How It Works

### 🔹 Step 1: Choose Algorithm
Users select one of three algorithms: **AES**, **RSA**, or **ECC**.

### 🔹 Step 2: Encrypt

- **AES**: Input plaintext and key (manual or auto-generated), system returns ciphertext and IV.
- **RSA**: System generates key pairs, encryption is done using receiver’s public key.
- **ECC**: Generates key pairs + IV, and derives a shared AES key in the backend (via ECDH).

### 🔹 Step 3: Decrypt

- **AES**: Requires ciphertext, key, and IV.
- **RSA**: Requires ciphertext and receiver’s private key.
- **ECC**: Requires ciphertext, IV, receiver’s private key, and sender’s public key to reconstruct the AES key and decrypt.

---

## 📂 Project Structure

```
.
├── app.py # Flask backend (handles logic, encryption/decryption)
├── template/
│ └── index.html # Frontend (HTML, CSS, JS)
├── Security Project.pdf # Presentation explaining the concept
└── README.md # Project documentation
```

---

## 📦 Requirements

- Python 3.x
- Flask
- Cryptography libraries:
  - `pycryptodome` (for AES, RSA)
  - `cryptography` (for ECC)

---

## 🧪 Run Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/cipherguard.git
   cd cipherguard
   ```
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Start the Flask app
   ```bash
   python app.py
   ```
4. Open the app in your browser
   ```bash
   http://localhost:5000
   ```

---

## 🙌 Acknowledgements

- This project was developed as part of an academic cybersecurity initiative.
- Special thanks to our mentors and reviewers who provided guidance on cryptographic protocols.
- Libraries and frameworks used:
    - Flask
    - PyCryptodome
    - Cryptography

---

## 👨‍💻 Authors

- Ahmed Mnaouer
- Roua Abassi

---

## 📄 License

This project is intended for educational use. Feel free to fork, use, and improve with attribution.
