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

import click
from click_aliases import ClickAliasedGroup

from dtcli.constants import *
from dtcli.utils import *

from dtcli import building
from dtcli import signing
from dtcli import __version__

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS, cls=ClickAliasedGroup)
@click.version_option(version=__version__)
def main():
    pass


@main.group(aliases=["extensions", "ext"])
def extension():
    pass


@extension.command(
    help="creates CA key and certificate, needed to create developer certificate used for extension signing"
)
@click.option(
    "--ca-cert",
    default=DEFAULT_CA_CERT,
    help="CA certificate. Default: " + DEFAULT_CA_CERT,
)
@click.option(
    "--ca-key",
    default=DEFAULT_CA_KEY,
    help="CA key. Default: " + DEFAULT_CA_KEY,
)
def genca(**kwargs):
    ca_cert_file_path = kwargs["ca_cert"]
    require_is_not_dir(ca_cert_file_path)
    check_file_exists(ca_cert_file_path, KeyGenerationError)

    ca_key_file_path = kwargs["ca_key"]
    require_is_not_dir(ca_key_file_path)
    check_file_exists(ca_key_file_path, KeyGenerationError)

    signing.generate_ca(ca_cert_file_path, ca_key_file_path)


@extension.command(
    help="creates developer key and certificate used for extension signing"
)
@click.option(
    "--ca-cert",
    default=DEFAULT_CA_CERT,
    help="CA certificate. Default: " + DEFAULT_CA_CERT,
)
@click.option(
    "--ca-key",
    default=DEFAULT_CA_KEY,
    help="CA key. Default: " + DEFAULT_CA_KEY,
)
@click.option(
    "--dev-cert",
    default=DEFAULT_DEV_CERT,
    help="Developer certificate. Default: " + DEFAULT_DEV_CERT,
)
@click.option(
    "--dev-key",
    default=DEFAULT_DEV_KEY,
    help="Developer key. Default: " + DEFAULT_DEV_KEY,
)
def gendevcert(**kwargs):
    ca_cert_file_path = kwargs["ca_cert"]
    ca_key_file_path = kwargs["ca_key"]
    dev_cert_file_path = kwargs["dev_cert"]
    dev_key_file_path = kwargs["dev_key"]

    require_file_exists(ca_cert_file_path)
    require_file_exists(ca_key_file_path)
    require_is_not_dir(dev_cert_file_path)
    require_is_not_dir(dev_key_file_path)

    check_file_exists(dev_key_file_path, KeyGenerationError)
    check_file_exists(dev_cert_file_path, KeyGenerationError)

    signing.generate_cert(
        ca_cert_file_path,
        ca_key_file_path,
        dev_cert_file_path,
        dev_key_file_path,
    )


@extension.command(
    help="builds extension file from the given extension directory (`extension' in current dir. is the default)"
)
@click.option(
    "--extension-directory",
    default=DEFAULT_EXTENSION_DIR,
    help="Directory where extension files are. Default: "
    + DEFAULT_EXTENSION_DIR,
)
@click.option(
    "--target-directory",
    default=DEFAULT_TARGET_PATH,
    help="Directory where extension package should be written. Default: "
    + DEFAULT_TARGET_PATH,
)
@click.option(
    "--certificate",
    default=DEFAULT_DEV_CERT,
    help="Certificate used for signing. Default: " + DEFAULT_DEV_CERT,
)
@click.option(
    "--private-key",
    default=DEFAULT_DEV_KEY,
    help="Private key used for signing. Default: " + DEFAULT_DEV_KEY,
)
@click.option(
    "--keep-intermediate-files",
    is_flag=True,
    default=False,
    help="Do not delete the signature and `extension.zip' files after building extension archive",
)
def build(**kwargs):
    extension_dir_path = kwargs["extension_directory"]
    require_dir_exists(extension_dir_path)

    target_dir_path = kwargs["target_directory"]
    if os.path.exists(target_dir_path):
        require_dir_exists(target_dir_path)
        if not os.path.isdir(target_dir_path):
            print("%s is not a directory, aborting!" % target_dir_path)
            return
    else:
        print("Creating target directory: %s" % target_dir_path)
        os.makedirs(target_dir_path, exist_ok=True)

    extension_zip_path = os.path.join(target_dir_path, EXTENSION_ZIP)
    extension_zip_sig_path = os.path.join(target_dir_path, EXTENSION_ZIP_SIG)

    certificate_file_path = kwargs["certificate"]
    require_file_exists(certificate_file_path)
    private_key_file_path = kwargs["private_key"]
    require_file_exists(private_key_file_path)

    building.build_extension(
        extension_dir_path,
        extension_zip_path,
        extension_zip_sig_path,
        target_dir_path,
        certificate_file_path,
        private_key_file_path,
        kwargs["keep_intermediate_files"],
    )


if __name__ == "__main__":
    main()
