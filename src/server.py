#!/usr/bin/env python3
# src/server_phase4.py
import argparse, json, socket, os, secrets, hmac, hashlib
from pathlib import Path
from datetime import datetime
import pymysql

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

from phase4_common import (sha256, sha256_hex, b64, ub64,
                           aes_decrypt_ivcipher, aes_encrypt_ivcipher,
                           load_private_key, load_public_key_from_cert_pem,
                           sign_bytes, verify_signature, now_millis)

# reuse DB helper if you created db.py
from db import db_connect

CERT_DIR = Path("certs")
LOG_DIR = Path("logs"); LOG_DIR.mkdir(parents=True, exist_ok=True)

def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())

def recv_json_line(conn):
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            return json.loads(line.decode())

def verify_cert_signed_by_ca(cert_pem: bytes, ca_pem: bytes) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca = x509.load_pem_x509_certificate(ca_pem)
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, asym_padding.PKCS1v15(), cert.signature_hash_algorithm)
        now = datetime.utcnow()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            return False
        return True
    except Exception as e:
        print("CERT verify error:", e)
        return False

def perform_dh_gen(key_size=2048):
    params = dh.generate_parameters(generator=2, key_size=key_size)
    priv = params.generate_private_key()
    pub_y = priv.public_key().public_numbers().y
    return params, priv, pub_y

def derive_aes_from_shared(shared_bytes: bytes) -> bytes:
    return sha256(shared_bytes)[:16]

def cert_fingerprint_hex(cert_pem: bytes) -> str:
    return sha256(cert_pem).hex()

def append_transcript(path: Path, line: str):
    with open(path, "ab") as f:
        f.write(line.encode() + b"\n")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--cert", default=str(CERT_DIR / "server.pem"))
    p.add_argument("--key", default=str(CERT_DIR / "server.key"))
    p.add_argument("--ca", default=str(CERT_DIR / "ca.pem"))
    args = p.parse_args()

    server_cert_p = Path(args.cert); server_key_p = Path(args.key); ca_p = Path(args.ca)
    assert server_cert_p.exists() and server_key_p.exists() and ca_p.exists()

    server_priv = load_private_key(server_key_p)
    server_cert_pem = server_cert_p.read_bytes()
    ca_pem = ca_p.read_bytes()

    sock = socket.socket(); sock.bind((args.host, args.port)); sock.listen(1)
    print("Listening", args.host, args.port)
    while True:
        conn, addr = sock.accept()
        print("Conn from", addr)
        session_id = secrets.token_hex(8)
        transcript_path = LOG_DIR / f"transcript-{session_id}.log"
        last_seq_seen = 0
        try:
            # --- hello ---
            j = recv_json_line(conn)
            if j.get("type") != "hello": send_json(conn, {"type":"bad_proto"}); conn.close(); continue
            client_cert_pem = j.get("cert").encode(); client_nonce = j.get("nonce")
            if not verify_cert_signed_by_ca(client_cert_pem, ca_pem):
                send_json(conn, {"type":"bad_cert"}); conn.close(); continue
            send_json(conn, {"type":"server_hello", "cert": server_cert_p.read_text(), "nonce": secrets.token_hex(16)})

            # --- temp DH for auth (same as Phase3) ---
            params, priv, puby = perform_dh_gen()
            p_int = params.parameter_numbers().p; g_int = params.parameter_numbers().g
            send_json(conn, {"type":"dh_params", "p": str(p_int), "g": str(g_int), "server_pub": str(puby)})
            j2 = recv_json_line(conn)
            client_pub_y = int(j2.get("client_pub"))
            client_pub = dh.DHPublicNumbers(client_pub_y, params.parameter_numbers()).public_key()
            shared = priv.exchange(client_pub)
            K_temp = derive_aes_from_shared(shared)

            j3 = recv_json_line(conn)
            ivct = ub64(j3.get("payload"))
            try:
                pt = aes_decrypt_ivcipher(K_temp, ivct)
            except Exception as e:
                send_json(conn, {"type":"auth_fail","reason":"decrypt"})
                conn.close(); continue
            auth = json.loads(pt.decode())

            # replay check
            if auth.get("client_nonce") != client_nonce:
                send_json(conn, {"type":"auth_fail","reason":"replay"}); conn.close(); continue

            # simple register/login handling (like Phase3)
            db = db_connect()
            cur = db.cursor()
            action = auth.get("action"); username = auth.get("username"); password = auth.get("password"); email = auth.get("email")
            if action == "register":
                cur.execute("SELECT id FROM users WHERE username=%s OR email=%s LIMIT 1", (username, email))
                if cur.fetchone():
                    send_json(conn, {"type":"auth_fail","reason":"taken"}); conn.close(); continue
                salt = os.urandom(16).hex()
                pwd_hash = hashlib.sha256(bytes.fromhex(salt) + password.encode()).hexdigest()
                cur.execute("INSERT INTO users (username,email,salt,pwd_hash) VALUES (%s,%s,%s,%s)", (username,email,salt,pwd_hash))
                send_json(conn, {"type":"auth_ok","message":"registered"})
            elif action == "login":
                cur.execute("SELECT id,salt,pwd_hash FROM users WHERE username=%s LIMIT 1", (username,))
                row = cur.fetchone()
                if not row:
                    send_json(conn, {"type":"auth_fail","reason":"no_user"}); conn.close(); continue
                computed = hashlib.sha256(bytes.fromhex(row["salt"]) + password.encode()).hexdigest()
                if not hmac.compare_digest(computed, row["pwd_hash"]):
                    send_json(conn, {"type":"auth_fail","reason":"bad_creds"}); conn.close(); continue
                send_json(conn, {"type":"auth_ok","message":"login"})
            else:
                send_json(conn, {"type":"auth_fail","reason":"unknown"}); conn.close(); continue

            # Session DH (fresh)
            sess_params, sess_priv, sess_puby = perform_dh_gen()
            p2 = sess_params.parameter_numbers().p; g2 = sess_params.parameter_numbers().g
            send_json(conn, {"type":"session_dh","p":str(p2),"g":str(g2),"server_pub":str(sess_puby)})
            j4 = recv_json_line(conn)
            client_pub2 = int(j4.get("client_pub"))
            client_pub_obj2 = dh.DHPublicNumbers(client_pub2, sess_params.parameter_numbers()).public_key()
            shared2 = sess_priv.exchange(client_pub_obj2)
            K_session = derive_aes_from_shared(shared2)
            print("Session key:", K_session.hex())

            # compute client cert fingerprint for transcript
            client_cert_fp = sha256(client_cert_pem).hex()
            server_cert_fp = sha256(server_cert_pem).hex()

            # interactive signed message loop: server will receive messages, verify signature, decrypt, append, sign replies
            server_seq_out = 0
            server_seq_in = 0

            # send "ready" to client
            send_json(conn, {"type":"session_ready"})
            # loop
            while True:
                jmsg = recv_json_line(conn)
                if jmsg.get("type") == "msg":
                    seq = int(jmsg.get("seqno"))
                    ts = int(jmsg.get("ts"))
                    ct_b64 = jmsg.get("ct")
                    sig_b64 = jmsg.get("sig")
                    # verify seq monotonic
                    if seq <= server_seq_in:
                        send_json(conn, {"type":"error","reason":"replay_or_out_of_order"}); continue
                    # verify signature over (seq||ts||ct_bytes)
                    seq_bytes = seq.to_bytes(8,"big")
                    ts_bytes = ts.to_bytes(8,"big")
                    ct_bytes = ub64(ct_b64)
                    digest = sha256(seq_bytes + ts_bytes + ct_bytes)
                    try:
                        client_pubkey = load_public_key_from_cert_pem(client_cert_pem)
                        verify_signature(client_pubkey, ub64(sig_b64), digest)
                    except Exception as e:
                        send_json(conn, {"type":"error","reason":"sig_fail"}); continue
                    # signature ok, decrypt
                    try:
                        ptmsg = aes_decrypt_ivcipher(K_session, ct_bytes)
                    except Exception as e:
                        send_json(conn, {"type":"error","reason":"decrypt_fail"}); continue
                    server_seq_in = seq
                    # append transcript line
                    line = f"IN|{seq}|{ts}|{ct_b64}|{sig_b64}|{client_cert_fp}"
                    append_transcript(transcript_path, line)
                    print("Client says:", ptmsg.decode(errors="ignore"))
                    # prepare reply
                    server_seq_out += 1
                    reply_txt = b"echo: " + ptmsg
                    ct_reply = aes_encrypt_ivcipher(K_session, reply_txt)
                    seq_b = server_seq_out.to_bytes(8,"big"); ts_b = now_millis().to_bytes(8,"big")
                    digest_reply = sha256(seq_b + ts_b + ct_reply)
                    sig_reply = sign_bytes(load_private_key(server_key_p), digest_reply)
                    send_json(conn, {"type":"msg","seqno": server_seq_out, "ts": int(now_millis()), "ct": b64(ct_reply), "sig": b64(sig_reply)})
                    # append sent line
                    line2 = f"OUT|{server_seq_out}|{int(now_millis())}|{b64(ct_reply)}|{b64(sig_reply)}|{server_cert_fp}"
                    append_transcript(transcript_path, line2)
                elif jmsg.get("type") == "close":
                    # client asks to close; create receipt and send
                    # compute transcript hash
                    with open(transcript_path, "rb") as f:
                        allb = f.read()
                    thash = sha256(allb)
                    sig = sign_bytes(load_private_key(server_key_p), thash)
                    send_json(conn, {"type":"receipt", "transcript_hash": thash.hex(), "sig": b64(sig), "cert_fp": server_cert_fp})
                    # wait for client's receipt
                    jrec = recv_json_line(conn)
                    if jrec.get("type") == "receipt":
                        # verify client's signature over their transcript hash using client's cert
                        client_thash = bytes.fromhex(jrec.get("transcript_hash"))
                        client_sig = ub64(jrec.get("sig"))
                        client_pubkey = load_public_key_from_cert_pem(client_cert_pem)
                        try:
                            verify_signature(client_pubkey, client_sig, client_thash)
                            print("Client receipt verified.")
                        except Exception as e:
                            print("Client receipt verification failed:", e)
                    print("Session closed, saving transcript at", transcript_path)
                    conn.close()
                    break
                else:
                    send_json(conn, {"type":"error","reason":"unknown_msg"})
            # loop ends, connection closed, server awaits next
        except Exception as e:
            print("Conn error:", e)
            try: conn.close()
            except: pass

if __name__ == "__main__":
    main()
