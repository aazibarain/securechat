#!/usr/bin/env python3
# src/client_phase4.py
import argparse, json, socket, secrets, os, time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

from phase4_common import (sha256, b64, ub64, aes_encrypt_ivcipher, aes_decrypt_ivcipher,
                           load_private_key, load_public_key_from_cert_pem, sign_bytes, verify_signature, now_millis)

CERT_DIR = Path("certs")

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
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, __import__("cryptography.hazmat.primitives.asymmetric.padding", fromlist=["PKCS1v15"]).PKCS1v15(), cert.signature_hash_algorithm)
        now = __import__("datetime").datetime.utcnow()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            return False
        return True
    except Exception as e:
        print("CERT verify error (client):", e)
        return False

def perform_dh_from_params(p_int, g_int):
    pn = dh.DHParameterNumbers(p_int, g_int)
    params = pn.parameters()
    priv = params.generate_private_key()
    puby = priv.public_key().public_numbers().y
    return params, priv, puby

def derive_aes_from_shared(shared_bytes: bytes) -> bytes:
    return sha256(shared_bytes)[:16]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--cert", default=str(CERT_DIR / "client.pem"))
    p.add_argument("--key", default=str(CERT_DIR / "client.key"))
    p.add_argument("--ca", default=str(CERT_DIR / "ca.pem"))
    p.add_argument("--action", choices=["register","login"], default="register")
    p.add_argument("--username", default="alice")
    p.add_argument("--password", default="password123")
    p.add_argument("--email", default="a@x.com")
    args = p.parse_args()

    client_cert_p = Path(args.cert); client_key_p = Path(args.key); ca_p = Path(args.ca)
    assert client_cert_p.exists() and client_key_p.exists() and ca_p.exists()

    client_priv = load_private_key(client_key_p)
    client_cert_pem = client_cert_p.read_bytes()
    ca_pem = ca_p.read_bytes()

    s = socket.socket(); s.connect((args.host, args.port))
    print("Connected")

    client_nonce = secrets.token_hex(16)
    send_json(s, {"type":"hello", "cert": client_cert_p.read_text(), "nonce": client_nonce})

    j = recv_json_line(s)
    if j.get("type") != "server_hello": print("server hello fail", j); s.close(); return
    server_cert_pem = j.get("cert").encode()
    if not verify_cert_signed_by_ca(server_cert_pem, ca_pem):
        print("server cert verify fail"); s.close(); return

    # temp DH
    j2 = recv_json_line(s)
    params, priv, puby = perform_dh_from_params(int(j2.get("p")), int(j2.get("g")))
    server_pub = int(j2.get("server_pub"))
    send_json(s, {"type":"dh_client_pub", "client_pub": str(puby)})
    server_pub_key = dh.DHPublicNumbers(server_pub, params.parameter_numbers()).public_key()
    shared = priv.exchange(server_pub_key)
    K_temp = derive_aes_from_shared(shared)

    # send auth bound to client_nonce
    auth = {"action": args.action, "username": args.username, "password": args.password, "email": args.email, "client_nonce": client_nonce}
    pt = json.dumps(auth).encode()
    ivct = aes_encrypt_ivcipher(K_temp, pt)
    send_json(s, {"type":"auth", "payload": b64(ivct)})

    j3 = recv_json_line(s)
    print("Auth response:", j3)
    if j3.get("type") != "auth_ok": s.close(); return

    # session DH
    j4 = recv_json_line(s)
    if j4.get("type") != "session_dh": print("no session dh", j4); s.close(); return
    params2, priv2, puby2 = perform_dh_from_params(int(j4.get("p")), int(j4.get("g")))
    server_pub2 = int(j4.get("server_pub"))
    send_json(s, {"type":"session_client_pub", "client_pub": str(puby2)})
    server_pub_key2 = dh.DHPublicNumbers(server_pub2, params2.parameter_numbers()).public_key()
    shared2 = priv2.exchange(server_pub_key2)
    K_session = derive_aes_from_shared(shared2)
    print("K_session:", K_session.hex())

    # wait for ready
    jready = recv_json_line(s)

    # set seq numbers
    client_seq_out = 0
    client_seq_in = 0
    server_cert_fp = sha256(server_cert_pem).hex()
    client_cert_fp = sha256(client_cert_pem).hex()
    transcript_path = Path("logs") / f"transcript-{secrets.token_hex(8)}.log"
    transcript_path.parent.mkdir(parents=True, exist_ok=True)

    # interactive loop
    try:
        while True:
            msg = input("msg> ").strip()
            if not msg: continue
            if msg.lower() == "/exit":
                # send close request -> server will send receipt; client should send own receipt and exit
                send_json(s, {"type":"close"})
                # receive server receipt
                jrec = recv_json_line(s)
                if jrec.get("type") == "receipt":
                    thash = bytes.fromhex(jrec.get("transcript_hash"))
                    sig = ub64(jrec.get("sig"))
                    server_pubkey = load_public_key_from_cert_pem(server_cert_pem)
                    try:
                        verify_signature(server_pubkey, sig, thash)
                        print("Server receipt verified.")
                    except Exception as e:
                        print("Server receipt verify failed:", e)
                # compute and send client receipt
                with open(transcript_path, "rb") as f:
                    allb = f.read() if transcript_path.exists() else b""
                my_thash = sha256(allb)
                my_sig = sign_bytes(client_priv, my_thash)
                send_json(s, {"type":"receipt","transcript_hash": my_thash.hex(), "sig": b64(my_sig), "cert_fp": client_cert_fp})
                print("Sent client receipt. Closing.")
                s.close(); break

            # normal message
            client_seq_out += 1
            seq_b = client_seq_out.to_bytes(8,"big")
            ts = now_millis(); ts_b = ts.to_bytes(8,"big")
            ct = aes_encrypt_ivcipher(K_session, msg.encode())
            digest = sha256(seq_b + ts_b + ct)
            sig = sign_bytes(client_priv, digest)
            send_json(s, {"type":"msg", "seqno": client_seq_out, "ts": ts, "ct": b64(ct), "sig": b64(sig)})
            # append sent line
            with open(transcript_path, "ab") as f:
                f.write(f"OUT|{client_seq_out}|{ts}|{b64(ct)}|{b64(sig)}|{client_cert_fp}\n".encode())
            # wait for server reply
            j = recv_json_line(s)
            if j.get("type") == "msg":
                seq_in = int(j.get("seqno")); ts_in = int(j.get("ts")); ct_b64 = j.get("ct"); sig_b64 = j.get("sig")
                seqb = seq_in.to_bytes(8,"big"); tsb = ts_in.to_bytes(8,"big")
                ct_bytes = ub64(ct_b64)
                digest_in = sha256(seqb + tsb + ct_bytes)
                server_pubkey = load_public_key_from_cert_pem(server_cert_pem)
                try:
                    verify_signature(server_pubkey, ub64(sig_b64), digest_in)
                except Exception as e:
                    print("Server signature invalid:", e); continue
                # decrypt
                pt = aes_decrypt_ivcipher(K_session, ct_bytes)
                print("Server> ", pt.decode(errors="ignore"))
                # append received to transcript
                with open(transcript_path, "ab") as f:
                    f.write(f"IN|{seq_in}|{ts_in}|{ct_b64}|{sig_b64}|{server_cert_fp}\n".encode())
            else:
                print("No reply or error:", j)
    except KeyboardInterrupt:
        print("Interrupted; closing")
        s.close()

if __name__ == "__main__":
    main()
