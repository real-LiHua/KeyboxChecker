#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=C0114
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from defusedxml.ElementTree import ParseError, parse
from requests import get


def load_public_key_from_file(file_path):
    # pylint: disable=C0116
    with open(Path(__file__).parents[0] / file_path, "rb") as key_file:
        public_key = load_pem_public_key(key_file.read()).public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
    return public_key


revoked_keybox_list = get(  # pylint: disable=W3101
    "https://android.googleapis.com/attestation/status",
    headers={
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    },
).json()["entries"]

google_public_key = load_public_key_from_file("google.pem")
aosp_ec_public_key = load_public_key_from_file("aosp_ec.pem")
aosp_rsa_public_key = load_public_key_from_file("aosp_rsa.pem")
knox_public_key = load_public_key_from_file("knox.pem")

survivor, dead = Path("survivor"), Path("dead")
survivor.mkdir(0o755, exist_ok=True)
dead.mkdir(0o755, exist_ok=True)


def main():
    # pylint: disable=C0116,R0912,R0914,R0915
    with open("status.csv", "w", encoding="UTF-8") as csvfile:
        serial_numbers = []
        fieldnames = [
            "Serial number",
            "Subject",
            "Certificate within validity period",
            "Valid keychain",
            "Note",
            "Not found in Google's revoked keybox list",
        ]
        output = []
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for kb in Path(sys.argv[1] if len(sys.argv) > 1 else ".").glob("**/*.xml"):
            values = []
            try:
                root = parse(kb).getroot()
            except ParseError:
                continue
            pem_number = int(
                root.find(
                    ".//NumberOfCertificates"
                ).text.strip()  # pyright: reportOptionalMemberAccess=off
            )
            pem_certificates = [
                cert.text.strip()
                for cert in root.findall('.//Certificate[@format="pem"]')[:pem_number]
            ]
            certificate = x509.load_pem_x509_certificate(pem_certificates[0].encode())
            serial_number = hex(certificate.serial_number)[2:]
            if serial_number in serial_numbers:
                continue
            serial_numbers.append(serial_number)
            values.append(serial_number)

            values.append(
                " | ".join(
                    f"{rdn.oid._name}={rdn.value}"  # pylint: disable=W0212
                    for rdn in certificate.subject
                )
            )

            not_valid_before = certificate.not_valid_before_utc
            not_valid_after = certificate.not_valid_after_utc
            current_time = datetime.now(timezone.utc)
            is_valid = not_valid_before <= current_time <= not_valid_after
            values.append("✅" if is_valid else "❌")

            flag = True
            for i in range(pem_number - 1):
                son_certificate = x509.load_pem_x509_certificate(
                    pem_certificates[i].encode()
                )
                father_certificate = x509.load_pem_x509_certificate(
                    pem_certificates[i + 1].encode()
                )

                if son_certificate.issuer != father_certificate.subject:
                    flag = False
                    break
                signature = son_certificate.signature
                signature_algorithm = (
                    son_certificate.signature_algorithm_oid._name  # pylint: disable=W0212
                )
                tbs_certificate = son_certificate.tbs_certificate_bytes
                public_key = father_certificate.public_key()
                try:
                    if signature_algorithm in [
                        "sha256WithRSAEncryption",
                        "sha1WithRSAEncryption",
                        "sha384WithRSAEncryption",
                        "sha512WithRSAEncryption",
                    ]:
                        hash_algorithm = {
                            "sha256WithRSAEncryption": hashes.SHA256(),
                            "sha1WithRSAEncryption": hashes.SHA1(),
                            "sha384WithRSAEncryption": hashes.SHA384(),
                            "sha512WithRSAEncryption": hashes.SHA512(),
                        }[signature_algorithm]
                        padding_algorithm = padding.PKCS1v15()
                        public_key.verify(
                            signature,
                            tbs_certificate,
                            padding_algorithm,
                            hash_algorithm,
                        )
                    elif signature_algorithm in [
                        "ecdsa-with-SHA256",
                        "ecdsa-with-SHA1",
                        "ecdsa-with-SHA384",
                        "ecdsa-with-SHA512",
                    ]:
                        hash_algorithm = {
                            "ecdsa-with-SHA256": hashes.SHA256(),
                            "ecdsa-with-SHA1": hashes.SHA1(),
                            "ecdsa-with-SHA384": hashes.SHA384(),
                            "ecdsa-with-SHA512": hashes.SHA512(),
                        }[signature_algorithm]
                        padding_algorithm = ec.ECDSA(hash_algorithm)
                        public_key.verify(signature, tbs_certificate, padding_algorithm)
                    else:
                        raise ValueError("Unsupported signature algorithms")
                except Exception:  # pylint: disable=W0718
                    flag = False
                    break
            values.append("✅" if flag else "❌")

            root_public_key = (
                x509.load_pem_x509_certificate(pem_certificates[-1].encode())
                .public_key()
                .public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )
            )
            if root_public_key == google_public_key:
                values.append("✅ Google hardware attestation root certificate")
            elif root_public_key == aosp_ec_public_key:
                values.append("🟡 AOSP software attestation root certificate (EC)")
            elif root_public_key == aosp_rsa_public_key:
                values.append("🟡 AOSP software attestation root certificate (RSA)")
            elif root_public_key == knox_public_key:
                values.append("✅ Samsung Knox attestation root certificate")
            else:
                values.append("❌ Unknown root certificate")

            status = revoked_keybox_list.get(serial_number)

            kb.rename(
                (dead if status or not flag or not is_valid else survivor)
                / f"{serial_number}.xml"
            )
            values.append("✅" if not status else f"❌ {status['reason']}")

            output.append(dict(zip(fieldnames, values)))
        writer.writerows(sorted(output, key=lambda x: x[fieldnames[0]]))
