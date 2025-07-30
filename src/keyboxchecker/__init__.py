"""A module for checking the validity and revocation status of Keybox XML files."""

from __future__ import annotations

import argparse
import re
import sys
from enum import IntFlag, auto
from pathlib import Path
from time import time_ns
from typing import TYPE_CHECKING, Literal, no_type_check, override

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509 import (
    BasicConstraints,
    Certificate,
    ExtensionType,
    load_pem_x509_certificates,
)
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    Policy,
    PolicyBuilder,
    Store,
    VerifiedClient,
)
from defusedxml.ElementTree import ParseError, parse
from loguru import logger
from requests import get

if TYPE_CHECKING:
    from os import PathLike
    from xml.etree.ElementTree import Element

    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes


def load_public_key_from_file(file_path: str) -> PublicKeyTypes:
    with Path(__file__).resolve().with_name(file_path).open("rb") as key_file:
        return load_pem_public_key(key_file.read())


GOOGLE_PUBLIC_KEY = load_public_key_from_file("google.pem")
AOSP_EC_PUBLIC_KEY = load_public_key_from_file("aosp_ec.pem")
AOSP_REA_PUBLIC_KEY = load_public_key_from_file("aosp_rsa.pem")
KNOX_PUBLIC_KEY = load_public_key_from_file("knox.pem")

ROOTS = (GOOGLE_PUBLIC_KEY, AOSP_EC_PUBLIC_KEY, AOSP_REA_PUBLIC_KEY, KNOX_PUBLIC_KEY)

CERTIFICATE_REVOCATION_LIST: dict[str, dict[str, str]] = get(  # pyright:ignore[reportAny]
    "https://android.googleapis.com/attestation/status",
    {"ts": time_ns()},
    headers={
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    },
    timeout=30,
).json()["entries"]


def is_revoked(_policy: Policy, cert: Certificate, _extension: ExtensionType) -> None:
    if CERTIFICATE_REVOCATION_LIST.get(str(cert.serial_number)):
        pass


CA_POLICY = ExtensionPolicy.permit_all().require_present(
    BasicConstraints, Criticality.CRITICAL, is_revoked,
)
EE_POLICY = ExtensionPolicy.permit_all()
policy_builder = PolicyBuilder().extension_policies(
    ca_policy=CA_POLICY, ee_policy=EE_POLICY,
)
root_certs: list[Certificate] = []


class Error(IntFlag):
    Invalid_File_Path = auto()
    Invalid_Format = auto()

    Invalid_ecdsa_Private_Key = auto()
    Invalid_ecdsa_Certificate_Chain = auto()

    Invalid_rsa_Private_Key = auto()
    Invalid_rsa_Certificate_Chain = auto()

    Revoked = auto()


class Keybox:
    @no_type_check
    def __init__(self, path: PathLike[str] | Literal["str"]) -> None:
        self.path: Path = Path(path)
        self._flag: int = 0
        logger.debug(f"Initializing Keybox with path: {self.path}")
        try:
            self._root: Element | None = parse(self.path).getroot()
            logger.info(f"Successfully parsed XML: {self.path}")
        except FileNotFoundError:
            logger.warning(f"Path {self.path} does not exist")
            self._flag |= Error.Invalid_File_Path
        except ParseError as e:
            logger.exception(f"ParseError for {self.path}: {e}")
            self._flag |= Error.Invalid_Format
        self.status: str | None
        self.ecdsa_public_key: Ed25519PublicKey
        self.rsa_public_key: RSAPublicKey
        self._load_private_key("ecdsa")
        self._load_private_key("rsa")
        self._check("ecdsa")
        self._check("rsa")

    def __bool__(self) -> bool:
        """Returns True if the Keybox is valid, False otherwise."""
        return not self._flag

    @override
    def __eq__(self, flag: object) -> bool:
        return isinstance(flag, Error) and bool(self._flag & flag)

    def __neg__(self) -> None:
        self.path.unlink(missing_ok=True)

    def __rshift__(self, target: PathLike[str]) -> Path:
        return self.path.replace(Path(target) / self.path.name)

    def _clean(self, element: Element | None) -> str:
        if element is None:
            return ""
        text = element.text or ""
        text = re.sub(r"\s*\n\s*", "\n", text.strip())
        text = re.sub(r"<!--.*-->", "", text)
        return text.strip()

    def _load_private_key(self, algorithm: str) -> None:
        logger.debug(f"Loading private key for algorithm: {algorithm}")
        if algorithm not in {"ecdsa", "rsa"}:
            logger.error(f"Invalid algorithm: {algorithm}")
            msg = 'algorithm must be "ecdsa" or "rsa"'
            raise ValueError(msg)
        if self._root is None:
            logger.warning("XML root is None, cannot load private key")
            return
        try:
            pri_key = self._clean(self._root.find(f".//Key[@{algorithm=}]/PrivateKey"))
        except ParseError:
            logger.exception(
                f"ParseError while finding private key node for {algorithm}",
            )
            self._flag |= getattr(Error, f"Invalid_{algorithm}_Private_Key")
            return
        public_key = (
            pri_key
            and load_pem_private_key(pri_key.encode(), password=None).public_key()
        )
        if isinstance(public_key, (Ed25519PublicKey, RSAPublicKey)):
            logger.info(f"Loaded public key for {algorithm} successfully")
            setattr(self, f"{algorithm}_public_key", public_key)

    def _check(self, algorithm: str) -> VerifiedClient | None:
        if algorithm not in {"ecdsa", "rsa"}:
            logger.error(f"Invalid algorithm: {algorithm}")
            msg = 'algorithm must be "ecdsa" or "rsa"'
            raise ValueError(msg)
        if self._root is None:
            return None
        leaf, *intermediates, ca = load_pem_x509_certificates(
            "\n".join(
                map(
                    self._clean,
                    self._root.findall(
                        f'.//Key[@{algorithm=}]//Certificate[@format="pem"]',
                    ),
                ),
            ).encode(),
        )
        if ca.public_key() not in ROOTS:
            return None
        return (
            policy_builder.store(Store([ca]))
            .build_client_verifier()
            .verify(leaf, intermediates)
        )


@no_type_check
def main() -> None:
    """Main function to parse arguments, process keybox files, and move them to valid/revoked directories."""
    parser = argparse.ArgumentParser("keyboxchecker")
    parser.add_argument(
        "-a", "--aosp", action="store_true", help='AOSP keybox as "Survivor".',
    )
    parser.add_argument(
        "-o", "--output", default=".", type=Path, help="Output directory.",
    )
    parser.add_argument(
        "-p", "--path", default=".", type=Path, help="Keybox XML files directory.",
    )
    parser.add_argument(
        "-v",
        "--valid",
        default="valid",
        type=Path,
        help="Valid keybox XML files directory.",
    )
    parser.add_argument(
        "-r",
        "--revoked",
        default="revoked",
        type=Path,
        help="Revoked keybox XML files directory.",
    )
    parser.add_argument(
        "-l", "--log-level", default="INFO", type=logger.level, help="Log level.",
    )
    args = parser.parse_args()

    logger.remove()
    logger.add(
        sys.stderr,
        filter=lambda record: record["level"].no >= args.log_level.no,
        level=0,
    )

    args.valid.mkdir(0o755, exist_ok=True)
    args.revoked.mkdir(0o755, exist_ok=True)
    for keybox in map(Keybox, args.path.glob("**/*.xml")):
        logger.debug(f"Processing keybox: {keybox.path}")
        # NOTE:
        # match keybox:
        #    case Error.Invalid_Format:
        #        pass
        #    case Error.Revoked:
        #        keybox >> args.revoked
        #    case _:
        #        keybox >> args.valid
        if keybox:
            logger.info(f"Valid keybox: {keybox.path}")
            keybox >> args.valid
        elif keybox == Error.Revoked:
            logger.warning(f"Revoked keybox: {keybox.path}")
            keybox >> args.revoked
        else:
            logger.error(f"Failed keybox: {keybox.path}, error flag: {keybox._flag}")


__all__ = [
    "AOSP_EC_PUBLIC_KEY",
    "AOSP_REA_PUBLIC_KEY",
    "GOOGLE_PUBLIC_KEY",
    "KNOX_PUBLIC_KEY",
    "Error",
    "Keybox",
]


def __dir__() -> list[str]:
    return __all__


if __name__ == "__main__":
    main()
