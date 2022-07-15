# Copyright 2021 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import datetime

from asn1crypto import cms, util, x509, core, pem
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.backends import default_backend

from . import utils as dtcliutils
from . import constants


CHUNK_SIZE = 1024 * 1024

X509NameAttributes = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "L": NameOID.LOCALITY_NAME,
    "S": NameOID.STATE_OR_PROVINCE_NAME,
    "C": NameOID.COUNTRY_NAME,
}


def _generate_x509_name(attributes):
    names_attributes = []
    for name, oid in X509NameAttributes.items():
        if name in attributes and attributes[name]:
            names_attributes.append(crypto_x509.NameAttribute(oid, attributes[name]))

    return crypto_x509.Name(names_attributes)


def generate_ca(ca_cert_file_path, ca_key_file_path, subject, not_valid_after, passphrase=None):
    print("Generating CA...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_key_encryption = (
        serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    )
    with open(ca_key_file_path, "wb") as fp:
        fp.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=private_key_encryption,
            )
        )
    print("Wrote CA private key: %s" % ca_key_file_path)
    public_key = private_key.public_key()
    builder = crypto_x509.CertificateBuilder()
    builder = builder.subject_name(_generate_x509_name(subject))
    builder = builder.issuer_name(_generate_x509_name(subject))
    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(crypto_x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        crypto_x509.BasicConstraints(ca=True, path_length=0),
        critical=False,
    )
    subject_identifier = crypto_x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(
        subject_identifier,
        critical=False,
    )
    builder = builder.add_extension(
        crypto_x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_identifier),
        critical=False,
    )
    builder = builder.add_extension(
        crypto_x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    with open(ca_cert_file_path, "wb") as fp:
        fp.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("Wrote CA certificate: %s" % ca_cert_file_path)


def generate_cert(
    ca_cert_file_path,
    ca_key_file_path,
    dev_cert_file_path,
    dev_key_file_path,
    subject,
    not_valid_after,
    ca_passphrase=None,
    dev_passphrase=None,
    destination=None,
):
    if not (destination or (dev_cert_file_path and dev_key_file_path)):
        raise TypeError("either fused destination or cert *AND* key destination must be specified")

    if destination:
        dev_cert_file_path = destination
        dev_key_file_path = destination
        flags =  "a"
    else:
        flags = "w"

    print("Loading CA private key %s" % ca_key_file_path)
    with open(ca_key_file_path, "rb") as fp:
        ca_private_key = serialization.load_pem_private_key(
            fp.read(), password=ca_passphrase.encode() if ca_passphrase else None, backend=default_backend()
        )

    print("Loading CA certificate %s" % ca_cert_file_path)
    with open(ca_cert_file_path, "rb") as fp:
        ca_cert = crypto_x509.load_pem_x509_certificate(fp.read())
    subject_name = _generate_x509_name(subject)
    if ca_cert.issuer == subject_name:
        raise dtcliutils.KeyGenerationError("Certificate subject must be different from its issuer")


    print("Generating developer certificate...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_key_encryption = (
        serialization.BestAvailableEncryption(dev_passphrase.encode())
        if dev_passphrase
        else serialization.NoEncryption()
    )
    with open(dev_key_file_path, "wb") as fp:
        fp.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=private_key_encryption,
            )
        )

    public_key = private_key.public_key()
    print("Wrote developer private key: %s" % dev_key_file_path)

    builder = crypto_x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(ca_cert.issuer)
    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(crypto_x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        crypto_x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )
    try:
        subject_identifier = ca_cert.extensions.get_extension_for_class(crypto_x509.SubjectKeyIdentifier)
        builder = builder.add_extension(
            crypto_x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_identifier.value),
            critical=False,
        )
    except crypto_x509.ExtensionNotFound:
        pass
    builder = builder.add_extension(
        crypto_x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )
    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
    )

    with open(dev_cert_file_path, "b" + flags) as fp:
        fp.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("Wrote developer certificate: %s" % dev_cert_file_path)

    os.chmod(dev_key_file_path, constants.REQUIRED_PRIVATE_KEY_PERMISSIONS)


def sign_file(file_path, signature_file_path, certificate_file_path, private_key_file_path, dev_passphrase=None, _no_side_effect=False):
    if not _no_side_effect:
        print(
            "Signing %s using %s certificate and %s private key" % (file_path, certificate_file_path, private_key_file_path)
        )

    with open(private_key_file_path, "rb") as fp:
        private_key = serialization.load_pem_private_key(
            fp.read(), password=dev_passphrase.encode() if dev_passphrase else None, backend=default_backend()
        )
    sha256 = hashes.SHA256()
    hasher = hashes.Hash(sha256)
    with open(file_path, "rb") as fp:
        buf = fp.read(CHUNK_SIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = fp.read(CHUNK_SIZE)
    signature = private_key.sign(hasher.finalize(), padding.PKCS1v15(), utils.Prehashed(sha256))
    signed_data = cms.SignedData()
    signed_data["version"] = "v1"
    signed_data["encap_content_info"] = util.OrderedDict([("content_type", "data"), ("content", None)])
    signed_data["digest_algorithms"] = [util.OrderedDict([("algorithm", "sha256"), ("parameters", None)])]

    with open(certificate_file_path, "rb") as fp:
        der_bytes = fp.read()
        if pem.detect(der_bytes):
            type_name, headers, der_bytes = pem.unarmor(der_bytes)
        else:
            print("Wrong certificate format, expected PEM, aborting!")
            raise dtcliutils.ExtensionBuildError()

    cert = x509.Certificate.load(der_bytes)

    signed_data["certificates"] = [
        cert,
    ]

    signer_info = cms.SignerInfo()
    signer_info["version"] = 1
    signer_info["digest_algorithm"] = util.OrderedDict([("algorithm", "sha256"), ("parameters", None)])
    signer_info["signature_algorithm"] = util.OrderedDict([("algorithm", "rsassa_pkcs1v15"), ("parameters", core.Null)])
    signer_info["signature"] = signature
    signer_info["sid"] = cms.SignerIdentifier(
        {
            "issuer_and_serial_number": util.OrderedDict(
                [
                    ("issuer", cert.issuer),
                    ("serial_number", cert.serial_number),
                ]
            )
        }
    )

    signed_data["signer_infos"] = [
        signer_info,
    ]

    # TODO timestamping?
    # dump  ASN.1 object
    asn1obj = cms.ContentInfo()
    asn1obj["content_type"] = "signed_data"
    asn1obj["content"] = signed_data

    der_bytes = asn1obj.dump()
    pem_bytes = pem.armor("CMS", der_bytes)

    if not _no_side_effect:
        with open(signature_file_path, "wb+") as fp:
            fp.write(pem_bytes)
            print("Wrote signature file %s" % signature_file_path)
    else:
       return pem_bytes 
