#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GNP/1 mTLS — generiše CA, server i klijentski cert (ECDSA P-256).

  python3 gnp_mtls.py --dir ~/.gnp/pki
Ispisuje putanje. Fajlovi 0600, direktorij 0700.
"""
import argparse, datetime, ipaddress, os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, data, mode=0o600):
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.expanduser("~/.gnp/pki"))
    ap.add_argument("--days", type=int, default=365)
    a = ap.parse_args()
    os.makedirs(a.dir, mode=0o700, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name("GNP GNP CA")
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))

    def leaf(cn, eku, san=None):
        key = ec.generate_private_key(ec.SECP256R1())
        b = (x509.CertificateBuilder()
             .subject_name(_name(cn)).issuer_name(ca_name)
             .public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=a.days))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage([eku]), critical=False))
        if san:
            b = b.add_extension(san, critical=False)
        return key, b.sign(ca_key, hashes.SHA256())

    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"), x509.DNSName("gnp-node"), x509.DNSName("gnp-hub"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        # (add SAN IPs via --ip if needed)
    ])
    nkey, ncert = leaf("gnp-node", ExtendedKeyUsageOID.SERVER_AUTH, san)
    ckey, ccert = leaf("gnp-client", ExtendedKeyUsageOID.CLIENT_AUTH)

    _write(os.path.join(a.dir, "ca.pem"), ca_cert.public_bytes(serialization.Encoding.PEM))
    _write(os.path.join(a.dir, "ca.key"), _key_pem(ca_key))
    _write(os.path.join(a.dir, "node.pem"), ncert.public_bytes(serialization.Encoding.PEM))
    _write(os.path.join(a.dir, "node.key"), _key_pem(nkey))
    _write(os.path.join(a.dir, "client.pem"), ccert.public_bytes(serialization.Encoding.PEM))
    _write(os.path.join(a.dir, "client.key"), _key_pem(ckey))
    print("OK", a.dir)
    for f in ("ca.pem", "node.pem", "node.key", "client.pem", "client.key"):
        print(" ", os.path.join(a.dir, f))
    return 0


if __name__ == "__main__":
    sys.exit(main())
