import sys
import json
import os
import ssl
import socket
from base64 import b64encode
from datetime import datetime
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open("native_app.log", "a", encoding="utf-8") as logfile:
        logfile.write(f"{timestamp} - {message}\n")


# Load certificates from a single .pem file
def load_trusted_certificates(pem_file_path):
    certs = []
    try:
        with open(pem_file_path, 'rb') as f:
            pem_data = f.read().decode('utf-8')
            for cert_str in pem_data.split("-----END CERTIFICATE-----"):
                if "-----BEGIN CERTIFICATE-----" in cert_str:
                    cert_str = cert_str + "-----END CERTIFICATE-----"
                    try:
                        cert = x509.load_pem_x509_certificate(cert_str.encode('utf-8'), default_backend())
                        certs.append(cert)
                        log(f"Successfully loaded certificate: {cert.subject.rfc4514_string()}")
                    except Exception as e:
                        log(f"Error loading certificate: {e}")
    except Exception as e:
        log(f"Error loading certificates from {pem_file_path}: {e}")
    return certs

# Path to your single .pem file containing multiple certificates
mozilla_ca_certs = load_trusted_certificates("path/to/your/certs_bundle.pem")

def is_built_in_root(cert):
    try:
        for trusted_cert in mozilla_ca_certs:
            if cert.fingerprint(hashes.SHA256()) == trusted_cert.fingerprint(hashes.SHA256()):
                return True
    except Exception as e:
        log(f"Error checking if certificate is built-in root: {e}")
    return False

def get_certificate_info(cert):
    try:
        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
        raw_der = cert
        sha1_fingerprint = hashlib.sha1(raw_der).hexdigest()
        sha256_fingerprint = hashlib.sha256(raw_der).hexdigest()
        sha256_pub_key_info = hashlib.sha256(x509_cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
        
        return {
            "fingerprint": {
                "sha1": sha1_fingerprint,
                "sha256": sha256_fingerprint,
            },
            "isBuiltInRoot": is_built_in_root(x509_cert),
            "issuer": x509_cert.issuer.rfc4514_string(),
            "rawDER": list(raw_der),
            "serialNumber": str(x509_cert.serial_number),
            "subject": x509_cert.subject.rfc4514_string(),
            "subjectPublicKeyInfoDigest": {
                "sha256": b64encode(sha256_pub_key_info).decode('ascii')
            },
            "validity": {
                "start": x509_cert.not_valid_before.timestamp() * 1000,
                "end": x509_cert.not_valid_after.timestamp() * 1000
            }
        }
    except Exception as e:
        log(f"Error getting certificate info: {e}")
        return {}

def get_security_info(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain,
        )
        conn.connect((domain, 443))

        # Retrieve the full certificate chain
        der_cert_chain = conn.getpeercert(binary_form=True)
        log(f"Retrieved DER certificate chain for {domain}: {der_cert_chain}")
        
        pem_cert_chain = ssl.DER_cert_to_PEM_cert(der_cert_chain)
        log(f"Converted to PEM certificate chain for {domain}: {pem_cert_chain}")
        
        x509_chain = []
        for cert_str in pem_cert_chain.split("-----END CERTIFICATE-----\n"):
            if "-----BEGIN CERTIFICATE-----" in cert_str:
                cert_str = cert_str + "-----END CERTIFICATE-----\n"  # Ensure the certificate is complete
                try:
                    x509_cert = x509.load_pem_x509_certificate(cert_str.encode('utf-8'), default_backend())
                    x509_chain.append(x509_cert)
                except Exception as e:
                    log(f"Error loading X509 certificate for {domain}: {e}")
        
        certificates = [get_certificate_info(cert.public_bytes(encoding=serialization.Encoding.DER)) for cert in x509_chain]
        log(f"Parsed certificates for {domain}: {certificates}")

        security_info = {
            "certificates": certificates
        }

        return security_info
    except Exception as e:
        log(f"Error retrieving security info for {domain}: {e}")
        return {"error": str(e)}

def read_message():
    raw_length = sys.stdin.read(4)
    if not raw_length:
        sys.exit(0)
    message_length = int.from_bytes(raw_length.encode('utf-8'), byteorder='little')
    message = sys.stdin.read(message_length)
    return json.loads(message)

def send_message(message_content):
    message_json = json.dumps(message_content)
    sys.stdout.write(len(message_json).to_bytes(4, byteorder='little').decode('utf-8'))
    sys.stdout.write(message_json)
    sys.stdout.flush()

log("Starting native messaging host")

while True:
    try:
        received_message = read_message()
        log(f"Received message: {received_message}")
        if received_message['type'] == 'getSecurityInfo':
            domain = received_message['domain']
            security_info = get_security_info(domain)
            send_message({"securityInfo": security_info})
            log(f"Sent security info: {security_info}")
    except Exception as e:
        log(f"Error: {e}")
        send_message({"error": str(e)})