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
import re

from click_aliases import ClickAliasedGroup

from dtcli.constants import *
from dtcli.utils import *

from dtcli import building
from dtcli import signing
from dtcli import __version__
from dtcli import dev

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

def validate_parse_subject(ctx, param, value):
    if value is None:
        return None

    def split_pair_and_verify_key(pair):
        key, val = pair.replace("\\", "").split('=')
        if key not in signing.X509NameAttributes:
            raise click.BadParameter(f"subject attributes must be one of {list(signing.X509NameAttributes)}. Got '{key}' instead.")
        return key, val

    try:
        return(dict(map(split_pair_and_verify_key, filter(None, re.split(r"(?<!\\)\/", value)))))
        return value
    except ValueError:
        raise click.BadParameter(f"format must be '/key0=value0/key1=value1/...' got: '{value}'")


def _genca(ca_cert_path, ca_key_path, force, subject):
    if force:
        print("Forced generation option used. Already existing CA certificate files will be overwritten.")
        check_file_exists(ca_cert_path, KeyGenerationError)
        check_file_exists(ca_key_path, KeyGenerationError)
        signing.generate_ca(ca_cert_path, ca_key_path, subject)
        return

    if (
        check_file_exists(ca_cert_path, KeyGenerationError, warn_overwrite=False) and
        check_file_exists(ca_key_path, KeyGenerationError, warn_overwrite=False)
    ):
        raise KeyGenerationError(
            "CA certificate NOT generated! CA key and certificate already exist. Use --force option to generate anyway."
        )

    signing.generate_ca(ca_cert_path, ca_key_path, subject)


def _gendevcert(ca_cert_path, ca_key_path, dev_cert_path, dev_key_path, subject):
    require_file_exists(ca_cert_path)
    require_file_exists(ca_key_path)
    require_is_not_dir(dev_cert_path)
    require_is_not_dir(dev_key_path)

    check_file_exists(dev_cert_path, KeyGenerationError)
    check_file_exists(dev_key_path, KeyGenerationError)

    signing.generate_cert(
        ca_cert_path,
        ca_key_path,
        dev_cert_path,
        dev_key_path,
        subject
    )



@click.group(context_settings=CONTEXT_SETTINGS, cls=ClickAliasedGroup)
@click.version_option(version=__version__)
def main():
    pass


@main.group(aliases=["extensions", "ext"])
def extension():
    pass


@main.group(aliases=["extensions_dev", "ext_dev"])
def extension_dev():
    pass


@extension.command(
    help="creates CA key and certificate, needed to create developer certificate used for extension signing"
)
@click.option(
    "--ca-cert", default=DEFAULT_CA_CERT, show_default=True, help="CA certificate output path"
)
@click.option(
    "--ca-key", default=DEFAULT_CA_KEY, show_default=True, help="CA key output path"
)
@click.option(
    "--force", is_flag=True, help="overwrites already existing CA key and certificate"
)
@click.option(
    "--ca-subject", callback=validate_parse_subject, default="/CN=Default Extension CA/O=Some Company/OU=Extension CA",
    show_default=True, help="certificate subject. Accepted format is /key0=value0/key1=value1/..."
)
def genca(**kwargs):
    _genca(kwargs["ca_cert"], kwargs["ca_key"], kwargs["force"], kwargs["ca_subject"])



@extension.command(
    help="creates developer key and certificate used for extension signing"
)
@click.option(
    "--ca-cert", default=DEFAULT_CA_CERT, show_default=True, help="CA certificate input path"
)
@click.option(
    "--ca-key", default=DEFAULT_CA_KEY, show_default=True, help="CA key input path"
)
@click.option(
    "--dev-cert", default=DEFAULT_DEV_CERT, show_default=True, help="Developer certificate output path"
)
@click.option(
    "--dev-key", default=DEFAULT_DEV_KEY, show_default=True, help="Developer key output path"
)
@click.option(
    "--dev-subject", callback=validate_parse_subject, default="/CN=Some Developer/O=Some Company/OU=Extension Development",
    show_default=True, help="certificate subject. Accepted format is /key0=value0/key1=value1/..."
)
def gendevcert(**kwargs):
    _gendevcert(kwargs["ca_cert"], kwargs["ca_key"], kwargs["dev_cert"], kwargs["dev_key"], kwargs["dev_subject"])



@extension.command(
    help="creates CA key, CA certificate, developer key and developer certificate used for extension signing"
)
@click.option(
    "--ca-cert", default=DEFAULT_CA_CERT, show_default=True, help="CA certificate output path"
)
@click.option(
    "--ca-key", default=DEFAULT_CA_KEY, show_default=True, help="CA key output path"
)
@click.option(
    "--dev-cert", default=DEFAULT_DEV_CERT, show_default=True, help="Developer certificate output path"
)
@click.option(
    "--dev-key", default=DEFAULT_DEV_KEY, show_default=True, help="Developer key output path"
)
@click.option(
    "--force", is_flag=True, help="overwrites already existing CA key and certificate"
)
@click.option(
    "--ca-subject", callback=validate_parse_subject, default="/CN=Default Extension CA/O=Some Company/OU=Extension CA",
    show_default=True, help="certificate subject. Accepted format is /key0=value0/key1=value1/..."
)
@click.option(
    "--dev-subject", callback=validate_parse_subject, default="/CN=Some Developer/O=Some Company/OU=Extension Development",
    show_default=True, help="certificate subject. Accepted format is /key0=value0/key1=value1/..."
)
def gencerts(**kwargs):
    _genca(kwargs["ca_cert"], kwargs["ca_key"], kwargs["force"], kwargs["ca_subject"])
    _gendevcert(kwargs["ca_cert"], kwargs["ca_key"], kwargs["dev_cert"], kwargs["dev_key"], kwargs["dev_subject"])



@extension.command(
    help="builds extension file from the given extension directory (`extension' in current dir. is the default)"
)
@click.option(
    "--extension-directory",
    default=DEFAULT_EXTENSION_DIR, show_default=True,
    help="Directory where extension files are",
)
@click.option(
    "--target-directory",
    default=DEFAULT_TARGET_PATH, show_default=True,
    help="Directory where extension package should be written",
)
@click.option(
    "--certificate",
    default=DEFAULT_DEV_CERT, show_default=True,
    help="Certificate used for signing",
)
@click.option(
    "--private-key",
    default=DEFAULT_DEV_KEY, show_default=True,
    help="Private key used for signing",
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


@extension_dev.command(
    help="comand packs python package as a datasource. It uses pip to download all dependencies and create whl files"
)
@click.argument(
    "path-to-setup-py",
)
@click.option(
    "--additional-libraries-dir",
    default=None,
    help="Path to folder containing additional directories"
)
@click.option(
    "--extension-directory",
    default=DEFAULT_EXTENSION_DIR,
    help="Directory where extension files are. Default: "
    + DEFAULT_EXTENSION_DIR,
)
def prepare_python(path_to_setup_py, **kwargs):
    additional_libraries_dir = kwargs.get("additional_libraries_dir", None)
    extension_directory = kwargs["extension_directory"]

    return dev.pack_python_extension(
        setup_path=path_to_setup_py,
        target_path=extension_directory,
        additional_path=additional_libraries_dir)


if __name__ == "__main__":
    main()
