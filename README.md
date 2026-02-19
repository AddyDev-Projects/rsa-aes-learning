# Custom RSA-OAEP + AES-256-GCM Hybrid Encryption

A Python implementation of **RSA-OAEP** (SHA-256 + MGF1) combined with **AES-256-GCM** for hybrid encryption of large data.

>**WARNING:** This project is for educational purposes only.  
> DO NOT USE IN PRODUCTION. Security-critical applications require professionally reviewed cryptography libraries and protocols.
> This is just a practice project for educational purposes only. I made this to practice cryptography and not for professional use.

---

## Features

- 2048-bit RSA key generation  
- OAEP padding using SHA-256 and MGF1  
- AES-256-GCM for encrypting large data  
- Hybrid encryption: RSA encrypts AES key, AES encrypts the actual message  
- Supports both string and byte data

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/AddyDev-Projects/rsa-aes-learning
cd rsa-aes-learning
pip install -r requirements.txt
