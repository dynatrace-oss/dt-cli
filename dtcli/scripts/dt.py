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

import click
import datetime
import json
import re

from click_aliases import ClickAliasedGroup
import pathlib

from dtcli.constants import *
from dtcli.utils import *

from dtcli import building, delete_extension, api
from dtcli import signing
from dtcli import __version__
from dtcli import dev
from dtcli import server_api

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def validate_parse_subject(ctx, param, value):
    if value is None:
        return None

    def split_pair_and_verify_key(pair):
        key, val = pair.replace("\\", "").split("=")
        if key not in signing.X509NameAttributes:
            raise click.BadParameter(
                f"subject attributes must be one of {list(signing.X509NameAttributes)}. Got '{key}' instead."
            )
        return key, val

    try:
        return dict(map(split_pair_and_verify_key, filter(None, re.split(r"(?<!\\)\/", value))))
        return value
    except ValueError:
        raise click.BadParameter(f"format must be '/key0=value0/key1=value1/...' got: '{value}'")


def edit_other_option_if_true(ctx, param, value, other_name, edit_callback):
    if not value:
        return
    for p in ctx.command.params:
        if isinstance(p, click.Option) and p.name == other_name:
            edit_callback(p)


def _genca(ca_cert_path, ca_key_path, force, subject, days_valid, ca_passphrase):
    if force:
        print("Forced generation option used. Already existing CA certificate files will be overwritten.")
        check_file_exists(ca_cert_path, KeyGenerationError)
        check_file_exists(ca_key_path, KeyGenerationError)
        signing.generate_ca(
            ca_cert_path,
            ca_key_path,
            subject,
            datetime.datetime.today() + datetime.timedelta(days=days_valid),
            ca_passphrase,
        )
        return

    if check_file_exists(ca_cert_path, KeyGenerationError, warn_overwrite=False) and check_file_exists(
        ca_key_path, KeyGenerationError, warn_overwrite=False
    ):
        raise KeyGenerationError(
            "CA certificate NOT generated! CA key and certificate already exist. Use --force option to generate anyway."
        )

    signing.generate_ca(
        ca_cert_path,
        ca_key_path,
        subject,
        datetime.datetime.today() + datetime.timedelta(days=days_valid),
        ca_passphrase,
    )


def _gendevcert(
    ca_cert_path, ca_key_path, dev_cert_path, dev_key_path, subject, days_valid, ca_passphrase, dev_passphrase
):
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
        subject,
        datetime.datetime.today() + datetime.timedelta(days=days_valid),
        ca_passphrase,
        dev_passphrase,
    )

def token_load(ctx, param, value):
    """
    Function load token to application. First it checks if path is passed as argument. If not it takes
    default token localization defined in constants.py as DEFAULT_TOKEN_PATH, else gets token from file
    passed as argument. If file with token doesn't exist it checks if virtual variable DTCLI_API_TOKEN
    exist and returns token if so or error if not.
    """
    try:
        if value == '-':
            value = DEFAULT_TOKEN_PATH

        with open(value) as f:
            try:
                token = f.readlines()[0].rstrip()
            except IndexError:
                raise click.BadArgumentUsage("Token file exist but is empty. No token applied.")
        return token
    except FileNotFoundError:
        token = os.getenv("DTCLI_API_TOKEN")
        if token is None:
            raise click.UsageError("Virtual environment DTCLI_API_TOKEN doesn't exist. No token applied.")
        return token

# Walk around for token read from env if no file is provided, by default value is "-" and gets token from default file
# location if file doesn't exist takes token from virtual variable, else takes token from file passed as argument
api_token = click.argument("api-token-path", nargs=1, type=click.Path(exists=True, dir_okay=False, readable=True, resolve_path=True, allow_dash=True),
                           default="-", callback=token_load
                           )

@click.group(context_settings=CONTEXT_SETTINGS, cls=ClickAliasedGroup)
@click.version_option(version=__version__)
def main():
    """
    Dynatrace CLI is a command line utility that assists in signing, building and uploading extensions
    for Dynatrace Extensions 2.0 framework
    """
    pass


@main.group(aliases=["extensions", "ext"])
def extension():
    """
    Set of utilities for signing, building and uploading extensions

    \b
    Example flow:
        gencerts -> build -> upload
    """
    pass


@main.group(aliases=["extensions_dev", "ext_dev"], hidden=True)
def extension_dev():
    pass


@extension.command(
    help="Creates CA key and certificate, needed to create developer certificate used for extension signing"
)
@click.option("--ca-cert", default=DEFAULT_CA_CERT, show_default=True, help="CA certificate output path")
@click.option("--ca-key", default=DEFAULT_CA_KEY, show_default=True, help="CA key output path")
@click.option(
    "--ca-subject",
    callback=validate_parse_subject,
    default="/CN=Default Extension CA/O=Some Company/OU=Extension CA",
    show_default=True,
    help="Certificate subject. Accepted format is /key0=value0/key1=value1/...",
)
@click.option(
    "--ca-passphrase",
    type=str,
    prompt="CA private key passphrase",
    confirmation_prompt=True,
    hide_input=True,
    default="",
    help="Sets passphrase for CA private key encryption - private key is not encrypted if empty",
)
@click.option(
    "--no-ca-passphrase",
    default=False,
    is_flag=True,
    is_eager=True,
    help="Skips prompt for CA private key encryption passphrase - private key is not encrypted",
    callback=lambda c, p, v: edit_other_option_if_true(
        c, p, v, "ca_passphrase", lambda param: setattr(param, "prompt", None)
    ),
)
@click.option("--force", is_flag=True, help="Overwrites already existing CA key and certificate")
@click.option(
    "--days-valid",
    default=DEFAULT_CERT_VALIDITY,
    show_default=True,
    type=int,
    help="Number of days certificate will be valid",
)
def genca(**kwargs):
    _genca(
        kwargs["ca_cert"],
        kwargs["ca_key"],
        kwargs["force"],
        kwargs["ca_subject"],
        kwargs["days_valid"],
        kwargs["ca_passphrase"],
    )


@extension.command(help="Creates developer key and certificate used for extension signing")
@click.option("--ca-cert", default=DEFAULT_CA_CERT, show_default=True, help="CA certificate input path")
@click.option("--ca-key", default=DEFAULT_CA_KEY, show_default=True, help="CA key input path")
@click.option(
    "--ca-passphrase",
    type=str,
    prompt="CA private key passphrase",
    hide_input=True,
    default="",
    help="Passphrase used for CA private key encryption",
)
@click.option(
    "--no-ca-passphrase",
    default=False,
    is_flag=True,
    is_eager=True,
    help="Skips prompt for CA private key encryption passphrase",
    callback=lambda c, p, v: edit_other_option_if_true(
        c, p, v, "ca_passphrase", lambda param: setattr(param, "prompt", None)
    ),
)
@click.option("--dev-cert", default=DEFAULT_DEV_CERT, show_default=True, help="Developer certificate output path")
@click.option("--dev-key", default=DEFAULT_DEV_KEY, show_default=True, help="Developer key output path")
@click.option(
    "--dev-passphrase",
    type=str,
    prompt="Developer private key passphrase",
    confirmation_prompt=True,
    hide_input=True,
    default="",
    help="Sets passphrase for developer private key encryption - private key is not encrypted if empty",
)
@click.option(
    "--no-dev-passphrase",
    default=False,
    is_flag=True,
    is_eager=True,
    help="Skips prompt for developer private key encryption passphrase - private key is not encrypted",
    callback=lambda c, p, v: edit_other_option_if_true(
        c, p, v, "dev_passphrase", lambda param: setattr(param, "prompt", None)
    ),
)
@click.option(
    "--dev-subject",
    callback=validate_parse_subject,
    default="/CN=Some Developer/O=Some Company/OU=Extension Development",
    show_default=True,
    help="certificate subject. Accepted format is /key0=value0/key1=value1/...",
)
@click.option(
    "--days-valid",
    default=DEFAULT_CERT_VALIDITY,
    show_default=True,
    type=int,
    help="Number of days certificate will be valid",
)
def gendevcert(**kwargs):
    _gendevcert(
        kwargs["ca_cert"],
        kwargs["ca_key"],
        kwargs["dev_cert"],
        kwargs["dev_key"],
        kwargs["dev_subject"],
        kwargs["days_valid"],
        kwargs["ca_passphrase"],
        kwargs["dev_passphrase"],
    )


@extension.command(
    help="Creates CA key, CA certificate, developer key and developer certificate used for extension signing"
)
@click.option("--ca-cert", default=DEFAULT_CA_CERT, show_default=True, help="CA certificate output path")
@click.option("--ca-key", default=DEFAULT_CA_KEY, show_default=True, help="CA key output path")
@click.option(
    "--ca-passphrase",
    type=str,
    prompt="CA private key passphrase",
    confirmation_prompt=True,
    hide_input=True,
    default="",
    help="Sets passphrase for CA private key encryption - private key is not encrypted if empty",
)
@click.option(
    "--no-ca-passphrase",
    default=False,
    is_flag=True,
    is_eager=True,
    help="Skips prompt for CA private key encryption passphrase - private key is not encrypted",
    callback=lambda c, p, v: edit_other_option_if_true(
        c, p, v, "ca_passphrase", lambda param: setattr(param, "prompt", None)
    ),
)
@click.option(
    "--ca-subject",
    callback=validate_parse_subject,
    default="/CN=Default Extension CA/O=Some Company/OU=Extension CA",
    show_default=True,
    help="certificate subject. Accepted format is /key0=value0/key1=value1/...",
)
@click.option("--force", is_flag=True, help="overwrites already existing CA key and certificate")
@click.option("--dev-cert", default=DEFAULT_DEV_CERT, show_default=True, help="Developer certificate output path")
@click.option("--dev-key", default=DEFAULT_DEV_KEY, show_default=True, help="Developer key output path")
@click.option(
    "--dev-passphrase",
    type=str,
    prompt="Developer private key passphrase",
    confirmation_prompt=True,
    hide_input=True,
    default="",
    help="Sets passphrase for developer private key encryption - private key is not encrypted if empty",
)
@click.option(
    "--no-dev-passphrase",
    default=False,
    is_flag=True,
    is_eager=True,
    help="Skips prompt for developer private key encryption passphrase - private key is not encrypted",
    callback=lambda c, p, v: edit_other_option_if_true(
        c, p, v, "dev_passphrase", lambda param: setattr(param, "prompt", None)
    ),
)
@click.option(
    "--dev-subject",
    callback=validate_parse_subject,
    default="/CN=Some Developer/O=Some Company/OU=Extension Development",
    show_default=True,
    help="certificate subject. Accepted format is /key0=value0/key1=value1/...",
)
@click.option(
    "--days-valid",
    default=DEFAULT_CERT_VALIDITY,
    show_default=True,
    type=int,
    help="Number of days certificate will be valid",
)
def gencerts(**kwargs):
    _genca(
        kwargs["ca_cert"],
        kwargs["ca_key"],
        kwargs["force"],
        kwargs["ca_subject"],
        kwargs["days_valid"],
        kwargs["ca_passphrase"],
    )
    _gendevcert(
        kwargs["ca_cert"],
        kwargs["ca_key"],
        kwargs["dev_cert"],
        kwargs["dev_key"],
        kwargs["dev_subject"],
        kwargs["days_valid"],
        kwargs["ca_passphrase"],
        kwargs["dev_passphrase"],
    )


@extension.command(
    help=f"Builds extension package from the given extension directory (default: {DEFAULT_EXTENSION_DIR}) that contains extension.yaml and additional asset directories"
)
@click.option(
    "--extension-directory",
    default=DEFAULT_EXTENSION_DIR,
    show_default=True,
    help="Directory where the `extension.yaml' and other extension files are located",
)
@click.option(
    "--target-directory",
    default=DEFAULT_TARGET_PATH,
    show_default=True,
    help="Directory where extension package should be written",
)
@click.option(
    "--certificate",
    default=DEFAULT_DEV_CERT,
    show_default=True,
    help="Developer certificate used for signing",
)
@click.option(
    "--private-key",
    default=DEFAULT_DEV_KEY,
    show_default=True,
    help="Developer private key used for signing",
)
@click.option(
    "--dev-passphrase",
    type=str,
    prompt="Developer private key passphrase",
    hide_input=True,
    default="",
    help="Passphrase used for developer private key encryption",
)
@click.option(
    "--no-dev-passphrase",
    default=False,
    is_flag=True,
    is_eager=True,
    help="Skips prompt for developer private key encryption passphrase",
    callback=lambda c, p, v: edit_other_option_if_true(
        c, p, v, "dev_passphrase", lambda param: setattr(param, "prompt", None)
    ),
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
        kwargs["dev_passphrase"],
        kwargs["keep_intermediate_files"],
    )


@extension.command(help="Validates extension package using Dynatrace Cluster API")
@click.argument("extension-zip", type=click.Path(exists=True, readable=True))
@click.option(
    "--tenant-url", prompt=True, help="Dynatrace environment URL, e.g., https://<tenantid>.live.dynatrace.com"
)
@click.option(
    "--api-token",
    prompt=True,
    help="Dynatrace API token. Please note that token needs to have the 'Write extension' scope enabled.",
)
def validate(**kwargs):
    extension_zip = kwargs["extension_zip"]
    require_file_exists(extension_zip)
    server_api.validate(extension_zip, kwargs["tenant_url"], kwargs["api_token"])


@extension.command(help="Uploads extension package to the Dynatrace Cluster")
@click.argument("extension-zip", type=click.Path(exists=True, readable=True))
@click.option(
    "--tenant-url", prompt=True, help="Dynatrace environment URL, e.g., https://<tenantid>.live.dynatrace.com"
)
@click.option(
    "--api-token",
    prompt=True,
    help="Dynatrace API token. Please note that token needs to have the 'Write extension' scope enabled.",
)
def upload(**kwargs):
    extension_zip = kwargs["extension_zip"]
    require_file_exists(extension_zip)
    server_api.upload(extension_zip, kwargs["tenant_url"], kwargs["api_token"])


@extension.command(
    help="Download alert from choosen id (E|<id>). Token - API v1 scopes Read and Write Configuration."
)
@click.argument(
    "alert-id", nargs=1
)
@click.option(
    "--tenant-url", prompt=True, help="Dynatrace environment URL, e.g., https://<tenantid>.live.dynatrace.com"
)
@api_token
def alert(**kwargs):
    token = kwargs["api_token_path"]
    dt = api.DynatraceAPIClient(kwargs["tenant_url"], token=token)
    alert = dt.acquire_alert(kwargs["alert_id"])
    print(json.dumps(alert, indent=4))


@extension.command(
    help="Downloads all schemas from choosen version e.g. 1.235"
)
@click.argument(
    "version", nargs=1
)
@click.option(
    "--tenant-url", prompt=True, help="Dynatrace environment URL, e.g., https://<tenantid>.live.dynatrace.com"
)
@api_token
@click.option(
    "--download-dir",
    default=DEFAULT_SCHEMAS_DOWNLOAD_DIR, show_default=True,
    help="Directory where downloaded schema files will be saved.",
)
def schemas(**kwargs):
    token = kwargs["api_token_path"]
    dt = api.DynatraceAPIClient(kwargs["tenant_url"], token=token)
    version = dt.download_schemas(kwargs["version"], kwargs["download_dir"])
    print(f"Downloaded schemas for version {version}")


@extension.command(
    help="Delete extension from Dynatrace Cluster, Extension e.g. custom:com.dynatrace.extension.extension-name"
)
@click.argument(
    "extension", nargs=1
)
@click.option(
    "--tenant-url", prompt=True, help="Dynatrace environment URL, e.g., https://<tenantid>.live.dynatrace.com"
)
@api_token
def delete(**kwargs):
    token = kwargs["api_token_path"]
    delete_extension.wipe(fqdn=kwargs["extension"], tenant=kwargs["tenant_url"], token=token)


@extension_dev.command(
    help="Command packs python package as a datasource. It uses pip to download all dependencies and create whl files"
)
@click.argument(
    "path-to-setup-py",
)
@click.option("--additional-libraries-dir", default=None, help="Path to folder containing additional directories")
@click.option(
    "--extension-directory",
    default=DEFAULT_EXTENSION_DIR,
    help="Directory where extension files are. Default: " + DEFAULT_EXTENSION_DIR,
)
def prepare_python(path_to_setup_py, **kwargs):
    additional_libraries_dir = kwargs.get("additional_libraries_dir", None)
    extension_directory = kwargs["extension_directory"]

    return dev.pack_python_extension(
        setup_path=path_to_setup_py, target_path=extension_directory, additional_path=additional_libraries_dir
    )


if __name__ == "__main__":
    main()
