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
import os
import pytest

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from dtcli import signing
from dtcli import utils

def test_generate_ca():
    cert_path = "test_ca_certificate.crt"
    key_path = "test_ca_key.key"
    not_valid_after = datetime.datetime.today().replace(microsecond=0) + datetime.timedelta(days=123)
    passphrase = "secretpassphrase"
    signing.generate_ca(
        cert_path,
        key_path,
        {
            "CN": "Some Common Name",
            "O": "Some Org Name",
            "OU": "Some OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        not_valid_after,
        passphrase
    )
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)

    with open(cert_path, "rb") as fp:
        ca_cert = crypto_x509.load_pem_x509_certificate(fp.read())

    assert ca_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Common Name"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Org Name"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some OU"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Common Name"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Org Name"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some OU"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert ca_cert.not_valid_after == not_valid_after

    with open(key_path, "rb") as fp:
        ca_private_key = serialization.load_pem_private_key(fp.read(), password=passphrase.encode())
    assert (
        ca_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) ==
        ca_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )

    os.remove(cert_path)
    os.remove(key_path)

def test_generate_ca_with_rsa():
    cert_path = "test_ca_certificate.crt"
    key_path = "test_ca_key.key"
    not_valid_after = datetime.datetime.today().replace(microsecond=0) + datetime.timedelta(days=123)
    passphrase = "secretpassphrase"
    is_rsa = True

    signing.generate_ca(
        cert_path,
        key_path,
        {
            "CN": "Some Common Name",
            "O": "Some Org Name",
            "OU": "Some OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        not_valid_after,
        passphrase,
        is_rsa
    )
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)

    with open(cert_path, "rb") as fp:
        ca_cert = crypto_x509.load_pem_x509_certificate(fp.read())

    assert ca_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Common Name"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Org Name"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some OU"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert ca_cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Common Name"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Org Name"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some OU"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert ca_cert.not_valid_after == not_valid_after

    with open(key_path, "rb") as fp:
        ca_private_key = serialization.load_pem_private_key(fp.read(), password=passphrase.encode())
    assert (
        ca_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1) ==
        ca_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    )

    os.remove(cert_path)
    os.remove(key_path)

def test_generate_ca_empty_attributes():
    cert_path = "test_ca_certificate.crt"
    key_path = "test_ca_key.key"

    signing.generate_ca(
        cert_path,
        key_path,
        {},
        datetime.datetime.today() + datetime.timedelta(days=1)
    )
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)

    with open(cert_path, "rb") as fp:
        ca_cert = crypto_x509.load_pem_x509_certificate(fp.read())

    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)

    assert not ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)

    with open(key_path, "rb") as fp:
        ca_private_key = serialization.load_pem_private_key(fp.read(), password=None)
    assert (
        ca_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) ==
        ca_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )

    os.remove(cert_path)
    os.remove(key_path)

def test_generate_ca_empty_attributes_with_rsa():
    cert_path = "test_ca_certificate.crt"
    key_path = "test_ca_key.key"

    signing.generate_ca(
        cert_path,
        key_path,
        {},
        datetime.datetime.today() + datetime.timedelta(days=1),
        is_rsa = True
    )
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)

    with open(cert_path, "rb") as fp:
        ca_cert = crypto_x509.load_pem_x509_certificate(fp.read())

    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
    assert not ca_cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)

    assert not ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
    assert not ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)

    with open(key_path, "rb") as fp:
        ca_private_key = serialization.load_pem_private_key(fp.read(), password=None)
    assert (
        ca_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1) ==
        ca_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    )

    os.remove(cert_path)
    os.remove(key_path)

def test_generate_cert():
    ca_cert_path = "test_ca_certificate.crt"
    ca_key_path = "test_ca_key.key"
    ca_passphrase = "secretcapassphrase"

    signing.generate_ca(
        ca_cert_path,
        ca_key_path,
        {
            "CN": "Some Common Name",
            "O": "Some Org Name",
            "OU": "Some OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        datetime.datetime.today() + datetime.timedelta(days=1),
        ca_passphrase
    )
    assert os.path.exists(ca_cert_path)
    assert os.path.exists(ca_key_path)

    dev_cert_path = "test_dev_certificate.crt"
    dev_key_path = "test_dev_key.key"
    not_valid_after = datetime.datetime.today().replace(microsecond=0) + datetime.timedelta(days=123)
    dev_passphrase = "secretdevpassphrase"

    signing.generate_cert(
        ca_cert_path,
        ca_key_path,
        dev_cert_path,
        dev_key_path,
        {
            "CN": "Some Other Common Name",
            "O": "Some Other Org Name",
            "OU": "Some Other OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        not_valid_after,
        ca_passphrase,
        dev_passphrase
    )
    assert os.path.exists(dev_cert_path)
    assert os.path.exists(dev_key_path)

    with open(dev_cert_path, "rb") as fp:
        dev_cert = crypto_x509.load_pem_x509_certificate(fp.read())

    assert dev_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Common Name"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Org Name"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some OU"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert dev_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Other Common Name"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Other Org Name"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some Other OU"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert dev_cert.not_valid_after == not_valid_after

    with open(dev_key_path, "rb") as fp:
        dev_private_key = serialization.load_pem_private_key(fp.read(), password=dev_passphrase.encode())
    assert (
        dev_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) ==
        dev_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )

    os.remove(ca_cert_path)
    os.remove(ca_key_path)
    os.remove(dev_cert_path)
    os.remove(dev_key_path)

def test_generate_cert_with_rsa():
    ca_cert_path = "test_ca_certificate.crt"
    ca_key_path = "test_ca_key.key"
    ca_passphrase = "secretcapassphrase"
    is_rsa = True

    signing.generate_ca(
        ca_cert_path,
        ca_key_path,
        {
            "CN": "Some Common Name",
            "O": "Some Org Name",
            "OU": "Some OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        datetime.datetime.today() + datetime.timedelta(days=1),
        ca_passphrase,
        is_rsa
    )
    assert os.path.exists(ca_cert_path)
    assert os.path.exists(ca_key_path)

    dev_cert_path = "test_dev_certificate.crt"
    dev_key_path = "test_dev_key.key"
    not_valid_after = datetime.datetime.today().replace(microsecond=0) + datetime.timedelta(days=123)
    dev_passphrase = "secretdevpassphrase"
    is_rsa = True

    signing.generate_cert(
        ca_cert_path,
        ca_key_path,
        dev_cert_path,
        dev_key_path,
        {
            "CN": "Some Other Common Name",
            "O": "Some Other Org Name",
            "OU": "Some Other OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        not_valid_after,
        ca_passphrase,
        dev_passphrase,
        is_rsa
    )
    assert os.path.exists(dev_cert_path)
    assert os.path.exists(dev_key_path)

    with open(dev_cert_path, "rb") as fp:
        dev_cert = crypto_x509.load_pem_x509_certificate(fp.read())

    assert dev_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Common Name"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Org Name"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some OU"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert dev_cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert dev_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Some Other Common Name"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Some Other Org Name"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "Some Other OU"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == "Some Locality"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Some State"
    assert dev_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"

    assert dev_cert.not_valid_after == not_valid_after

    with open(dev_key_path, "rb") as fp:
        dev_private_key = serialization.load_pem_private_key(fp.read(), password=dev_passphrase.encode())
    assert (
        dev_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1) ==
        dev_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    )

    os.remove(ca_cert_path)
    os.remove(ca_key_path)
    os.remove(dev_cert_path)
    os.remove(dev_key_path)

def test_generate_cert_issuer_eq_subject():
    ca_cert_path = "test_ca_certificate.crt"
    ca_key_path = "test_ca_key.key"

    signing.generate_ca(
        ca_cert_path,
        ca_key_path,
        {
            "CN": "Some Common Name",
            "O": "Some Org Name",
            "OU": "Some OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        datetime.datetime.today() + datetime.timedelta(days=1)
    )
    assert os.path.exists(ca_cert_path)
    assert os.path.exists(ca_key_path)

    dev_cert_path = "test_dev_certificate.crt"
    dev_key_path = "test_dev_key.key"
    with pytest.raises(utils.KeyGenerationError):
        signing.generate_cert(
            ca_cert_path,
            ca_key_path,
            dev_cert_path,
            dev_key_path,
            {
                "CN": "Some Common Name",
                "O": "Some Org Name",
                "OU": "Some OU",
                "L": "Some Locality",
                "S": "Some State",
                "C": "PL"
            },
            datetime.datetime.today() + datetime.timedelta(days=1)
        )
    assert not os.path.exists(dev_cert_path)
    assert not os.path.exists(dev_key_path)

    os.remove(ca_cert_path)
    os.remove(ca_key_path)

def test_generate_cert_issuer_eq_subject_with_rsa():
    ca_cert_path = "test_ca_certificate.crt"
    ca_key_path = "test_ca_key.key"

    signing.generate_ca(
        ca_cert_path,
        ca_key_path,
        {
            "CN": "Some Common Name",
            "O": "Some Org Name",
            "OU": "Some OU",
            "L": "Some Locality",
            "S": "Some State",
            "C": "PL"
        },
        datetime.datetime.today() + datetime.timedelta(days=1),
        is_rsa = True
    )
    assert os.path.exists(ca_cert_path)
    assert os.path.exists(ca_key_path)

    dev_cert_path = "test_dev_certificate.crt"
    dev_key_path = "test_dev_key.key"
    with pytest.raises(utils.KeyGenerationError):
        signing.generate_cert(
            ca_cert_path,
            ca_key_path,
            dev_cert_path,
            dev_key_path,
            {
                "CN": "Some Common Name",
                "O": "Some Org Name",
                "OU": "Some OU",
                "L": "Some Locality",
                "S": "Some State",
                "C": "PL"
            },
            datetime.datetime.today() + datetime.timedelta(days=1),
            is_rsa = True
        )
    assert not os.path.exists(dev_cert_path)
    assert not os.path.exists(dev_key_path)

    os.remove(ca_cert_path)
    os.remove(ca_key_path)