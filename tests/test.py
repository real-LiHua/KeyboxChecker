from __future__ import annotations

from cryptography.x509 import BasicConstraints, load_pem_x509_certificates
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    PolicyBuilder,
    Store,
)
from defusedxml.ElementTree import parse

root = parse(open("./171.xml")).getroot()
leaf, *intermediates, ca = load_pem_x509_certificates(
    "\n".join(
        (x.text or "" for x in root.findall('.//Key[@algorithm="ecdsa"]//Certificate[@format="pem"]')),
    ).encode(),
)


def hook(_a, cert, _b) -> None:
    # crl
    pass


ca_policy = ExtensionPolicy.permit_all().require_present(
    BasicConstraints, Criticality.CRITICAL, hook,
)
ee_policy = ExtensionPolicy.permit_all()
store = Store(list({ca}))


verifier = (
    PolicyBuilder()
    .extension_policies(ca_policy=ca_policy, ee_policy=ee_policy)
    .store(store)
    .build_client_verifier()
)

chain = verifier.verify(leaf, intermediates)
