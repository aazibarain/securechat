# SecureChat — End-to-End Encrypted Messaging System  
**Course Assignment – Secure Chat Protocol Implementation**  
**Author:** Aazib
**Roll Number:** 22i-1031

---

## 📌 Overview
SecureChat is a custom, TLS-like secure messaging system implemented **from scratch** using Python.  
It provides:

- Root Certificate Authority (CA)  
- Server & Client X.509 certificates  
- Mutual certificate verification  
- Secure user registration & login  
- Diffie–Hellman (DH) authenticated key exchange  
- AES-128 encrypted chat  
- RSA signatures for message integrity  
- Replay protection via sequence numbers  
- Append-only transcript + signed session receipts  
- Tamper & invalid-certificate detection  


---

## 🗂 Repository Structure

securechat/
certs/
ca.pem
server.pem
client.pem
# private keys are NOT committed

src/
server.py
client.py
db.py
common_crypto.py
phase4_common.py

logs/
transcript-*.log
receipt_client.json
receipt_server.json

evidence/
pcap/
handshake_and_chat.pcap
tamper_replay.pcap
bad_cert.pcap
screenshots/
*.png
scripts/
replay_tamper.py
replay_auth.py

scripts/
gen_ca.py
gen_cert.py
inspect_cert.py
verify_chain.py

.env
requirements.txt
README.md
REPORT.pdf
TESTREPORT.pdf


---

## 🖥 Requirements
- macOS / Linux
- Python **3.10+**
- MySQL server
- OpenSSL
- Wireshark (for evidence)

---

## 🛠 1. Setup Instructions

### 1.1 Create virtual environment

python3 -m venv .venv
source .venv/bin/activate

1.2 Install dependencies
pip install -r requirements.txt

1.3 Configure .env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=securechat_user
DB_PASS=your_password
DB_NAME=securechat_db

## 2. PKI Setup (CA + Certificates)
2.1 Generate Root CA
python scripts/gen_ca.py --cn "SecureChat CA" --days 3650

2.2 Generate Server Certificate
python scripts/gen_cert.py --name server \
  --cn server.local --san "DNS:server.local,IP:127.0.0.1"

2.3 Generate Client Certificate
python scripts/gen_cert.py --name client \
  --cn client.local --san "DNS:client.local,IP:127.0.0.1"

2.4 Verify chain
openssl verify -CAfile certs/ca.pem certs/server.pem
openssl.verify -CAfile certs/ca.pem certs/client.pem

## 3. MySQL Setup

Login:

mysql -u root -p


Create DB & table:

CREATE DATABASE securechat_db;

USE securechat_db;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) UNIQUE,
  email VARCHAR(255) UNIQUE,
  salt VARCHAR(64) NOT NULL,
  pwd_hash CHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

## 4. Running the Server & Client
4.1 Start the Server
python src/server.py --host 127.0.0.1 --port 9000 \
  --cert certs/server.pem --key certs/server.key --ca certs/ca.pem

4.2 Register a new user
python src/client.py --action register \
  --username alice --password secret123 --email a@x.com

4.3 Login as existing user
python src/client.py --action login \
  --username alice --password secret123

4.4 Run client chat session
msg> hello
Server> echo: hello

msg> /exit
Session closed. Receipt generated.


This produces transcript and signed receipts.

## 5. Security Features Implemented
✔ PKI (Certificates)

Root CA (RSA-3072)

Server/client X.509 certs

Mutual certificate verification

Rejection of invalid/self-signed/expired certs

✔ Registration/Login

16-byte random salt per user

SHA256(salt || password) stored in DB

Passwords never logged or stored in plaintext

Credentials encrypted under temporary DH key (K_temp)

Constant-time password comparison

✔ Encrypted Chat

Ephemeral DH → AES session key (K_session)

AES-128-CBC with PKCS#7 padding

Encrypted request/response loop

✔ Integrity & Authenticity

SHA256(seq || ts || ciphertext)

RSA signature on every message

Signature verification on both ends

Strict replay protection (seqno monotonic)

✔ Non-Repudiation

Append-only message transcript

Final signed receipt over transcript hash

Offline verifiable using public keys

## 6. Test Evidence

Located in evidence/:

PCAPs

handshake_and_chat.pcap

tamper_replay.pcap

bad_cert.pcap

Screenshots

successful login/register

cert verification

message rejection (tamper/replay)

receipt verification

Test scripts

replay_tamper.py

replay_auth.py

These allow the TA to reproduce all attack tests.

## 7. How to Reproduce Tests (For TA)
To capture packets:
sudo tcpdump -i any tcp port 9000 -w evidence/pcap/test_run.pcap

To test tampering:
python evidence/scripts/replay_tamper.py

To test replay:
python evidence/scripts/replay_auth.py

## 8. Submission Contents

Your final submission includes:

Full source code (server/client/scripts)

CA + certificates (no private keys if forbidden)

README.md

REPORT.pdf

TESTREPORT.pdf

PCAP evidence

Screenshots

Transcript + receipts

.env template

requirements.txt

✔ Conclusion

This implementation provides a complete, fully functioning, secure end-to-end chat system that meets the full assignment rubric:

PKI

Secure authentication

Encrypted messaging

Integrity & signatures

Replay defense

Non-repudiation

Everything is reproducible and validated with PCAPs, transcripts, and signatures.
# securechat
# securechat
