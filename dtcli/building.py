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

import glob
import os
import os.path
import zipfile
import datetime

import yaml

from . import utils
from . import signing
from . import __version__

from .constants import EXTENSION_YAML, EXTENSION_ZIP, EXTENSION_ZIP_SIG

def _generate_build_comment():
    build_data = {
        "Generator": f"dt-cli {__version__}",
        "Creation-time": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    }

    return '\n'.join(': '.join(pair) for pair in build_data.items())

def _zip_extension(extension_dir_path, extension_zip_path):

    extension_yaml_path = os.path.join(extension_dir_path, EXTENSION_YAML)
    utils.require_file_exists(extension_yaml_path)

    utils.check_file_exists(extension_zip_path)
    print("Building %s from %s" % (extension_zip_path, extension_dir_path))

    try:
        with zipfile.ZipFile(extension_zip_path, "w") as zf:

            for file_path in glob.glob(
                os.path.join(extension_dir_path, "**"), recursive=True
            ):
                if os.path.isdir(file_path):
                    continue
                rel_path = os.path.relpath(file_path, extension_dir_path)
                print("Adding file: %s as %s" % (file_path, rel_path))
                zf.write(file_path, arcname=rel_path)

    except Exception as e:
        print(e)
        raise

    else:
        print("Wrote %s file" % extension_zip_path)


def _package(
    extension_dir_path,
    target_dir_path,
    extension_zip_path,
    extension_zip_sig_path,
):
    extension_yaml_path = os.path.join(extension_dir_path, EXTENSION_YAML)
    with open(extension_yaml_path, "r") as fp:
        metadata = yaml.safe_load(fp)
    extension_file_name = "%s-%s.zip" % (
        metadata["name"],
        metadata["version"],
    )

    utils.require_extension_name_valid(extension_file_name)
    extension_file_name = extension_file_name.replace(":", "_")

    extension_file_path = os.path.join(target_dir_path, extension_file_name)
    utils.check_file_exists(extension_file_path)
    try:
        with zipfile.ZipFile(extension_file_path, "w") as zf:
            zf.comment = bytes(_generate_build_comment(), "utf-8")
            zf.write(extension_zip_path, arcname=EXTENSION_ZIP)
            zf.write(extension_zip_sig_path, arcname=EXTENSION_ZIP_SIG)
    except Exception as e:
        print(e)
        raise
    else:
        print("Wrote %s file" % extension_file_path)


def build_extension(
    extension_dir_path,
    extension_zip_path,
    extension_zip_sig_path,
    target_dir_path,
    certificate_file_path,
    private_key_file_path,
    keep_intermediate_files=False,
):
    try:
        utils.require_dir_exists(extension_dir_path)
        utils.require_dir_exists(target_dir_path)
        _zip_extension(extension_dir_path, extension_zip_path)
        signing.sign_file(
            extension_zip_path,
            extension_zip_sig_path,
            certificate_file_path,
            private_key_file_path,
        )
        utils.require_file_exists(extension_zip_path)
        utils.require_file_exists(extension_zip_sig_path)
        _package(
            extension_dir_path,
            target_dir_path,
            extension_zip_path,
            extension_zip_sig_path,
        )
        if not keep_intermediate_files:
            utils.remove_files(
                [
                    extension_zip_path,
                    extension_zip_sig_path,
                ]
            )
    except utils.ExtensionBuildError:
        print("Failed to build extension! :-(")
    else:
        print("Extension built successfuly! :-)")
