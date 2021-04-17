# Copyright 2021 Dynatrace LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime

from asn1crypto import cms, util, x509, core, pem
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.backends import default_backend

from . import utils as dtcliutils


CHUNK_SIZE = 1024 * 1024


def generate_ca(ca_cert_file_path, ca_key_file_path):
    print("Generating CA...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    with open(ca_key_file_path, "wb") as fp:
        fp.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print("Wrote CA private key: %s" % ca_key_file_path)
    public_key = private_key.public_key()
    builder = crypto_x509.CertificateBuilder()
    builder = builder.subject_name(
        crypto_x509.Name(
            [
                crypto_x509.NameAttribute(
                    NameOID.COMMON_NAME, u"Default Extension CA"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, u"Some Company"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, u"Extension CA"
                ),
            ]
        )
    )
    builder = builder.issuer_name(
        crypto_x509.Name(
            [
                crypto_x509.NameAttribute(
                    NameOID.COMMON_NAME, u"Default Extension CA"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, u"Some Company"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, u"Extension CA"
                ),
            ]
        )
    )
    builder = builder.not_valid_before(
        datetime.datetime.today() - datetime.timedelta(days=1)
    )
    builder = builder.not_valid_after(datetime.datetime(2222, 2, 2))
    builder = builder.serial_number(crypto_x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        crypto_x509.BasicConstraints(ca=True, path_length=None),
        critical=False,
    )
    # TODO add aditional extension fields to be on par with openssl result
    # https://cryptography.io/en/latest/x509/reference.html#cryptography.x509.AuthorityKeyIdentifier
    # cryptography.x509.AuthorityKeyIdentifier(
    # https://cryptography.io/en/latest/x509/reference.html#cryptography.x509.SubjectKeyIdentifier
    # cryptography.x509.SubjectKeyIdentifier
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    with open(ca_cert_file_path, "wb") as fp:
        fp.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("Wrote CA certificate: %s" % ca_cert_file_path)


def generate_cert(
    ca_cert_file_path, ca_key_file_path, dev_cert_file_path, dev_key_file_path
):
    print("Loading CA private key %s" % ca_key_file_path)
    with open(ca_key_file_path, "rb") as fp:
        ca_private_key = serialization.load_pem_private_key(
            fp.read(), password=None, backend=default_backend()
        )

    print("Generating developer certificate...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    with open(dev_key_file_path, "wb") as fp:
        fp.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print("Wrote developer private key: %s" % dev_key_file_path)
    public_key = private_key.public_key()
    builder = crypto_x509.CertificateBuilder()
    builder = builder.subject_name(
        crypto_x509.Name(
            [
                crypto_x509.NameAttribute(
                    NameOID.COMMON_NAME, u"Some Developer"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, u"Some Company"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, u"Extension Development"
                ),
            ]
        )
    )
    # FIXME load CA cert and use proper values
    builder = builder.issuer_name(
        crypto_x509.Name(
            [
                crypto_x509.NameAttribute(
                    NameOID.COMMON_NAME, u"Default Extension CA"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, u"Some Company"
                ),
                crypto_x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, u"Extension CA"
                ),
            ]
        )
    )
    builder = builder.not_valid_before(
        datetime.datetime.today() - datetime.timedelta(days=1)
    )
    builder = builder.not_valid_after(datetime.datetime(2222, 2, 2))
    builder = builder.serial_number(crypto_x509.random_serial_number())
    builder = builder.public_key(public_key)
    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
    )

    with open(dev_cert_file_path, "wb") as fp:
        fp.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("Wrote developer certificate: %s" % dev_cert_file_path)


def sign_file(
    file_path,
    signature_file_path,
    certificate_file_path,
    private_key_file_path,
):
    print(
        "Signing %s using %s certificate and %s private key"
        % (file_path, certificate_file_path, private_key_file_path)
    )
    with open(private_key_file_path, "rb") as fp:
        private_key = serialization.load_pem_private_key(
            fp.read(), password=None, backend=default_backend()
        )
    sha256 = hashes.SHA256()
    hasher = hashes.Hash(sha256)
    with open(file_path, "rb") as fp:
        buf = fp.read(CHUNK_SIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = fp.read(CHUNK_SIZE)
    signature = private_key.sign(
        hasher.finalize(), padding.PKCS1v15(), utils.Prehashed(sha256)
    )
    signed_data = cms.SignedData()
    signed_data["version"] = "v1"
    signed_data["encap_content_info"] = util.OrderedDict(
        [("content_type", "data"), ("content", None)]
    )
    signed_data["digest_algorithms"] = [
        util.OrderedDict([("algorithm", "sha256"), ("parameters", None)])
    ]

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
    signer_info["digest_algorithm"] = util.OrderedDict(
        [("algorithm", "sha256"), ("parameters", None)]
    )
    signer_info["signature_algorithm"] = util.OrderedDict(
        [("algorithm", "rsassa_pkcs1v15"), ("parameters", core.Null)]
    )
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

    with open(signature_file_path, "wb+") as fp:
        der_bytes = asn1obj.dump()
        pem_bytes = pem.armor("CMS", der_bytes)
        fp.write(pem_bytes)
        print("Wrote signature file %s" % signature_file_path)
