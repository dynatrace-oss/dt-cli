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


import os.path
import stat
from pathlib import Path


EXTENSION_YAML = "extension.yaml"
EXTENSION_ZIP = "extension.zip"
EXTENSION_ZIP_SIG = "extension.zip.sig"
# TODO: convert to Pathlib
DEFAULT_TARGET_PATH = os.path.curdir
DEFAULT_EXTENSION_DIR = os.path.join(os.path.curdir, "extension")
DEFAULT_EXTENSION_DIR2 = os.path.join(os.path.curdir, "src")
DEFAULT_DEV_CERT = os.path.join(os.path.curdir, "developer.pem")
DEFAULT_DEV_KEY = os.path.join(os.path.curdir, "developer.key")
DEFAULT_CA_CERT = os.path.join(os.path.curdir, "ca.pem")
DEFAULT_CA_KEY = os.path.join(os.path.curdir, "ca.key")
EXTENSION_ZIP_BUNDLE = Path(DEFAULT_TARGET_PATH) / "bundle.zip"
# TODO: is this a good default value?
DEFAULT_CERT_VALIDITY = 365 * 3
DEFAULT_SCHEMAS_DOWNLOAD_DIR = os.path.join(os.path.curdir, "schemas")
DEFAULT_TOKEN_PATH = os.path.join(os.path.curdir, "secrets", "token")
DEFAULT_KEYCERT_PATH = os.path.join(os.path.curdir, "secrets", "developer.pem")
DEFAULT_BUILD_OUTPUT = Path(DEFAULT_TARGET_PATH) / EXTENSION_ZIP
REQUIRED_PRIVATE_KEY_PERMISSIONS = stat.S_IREAD
SCHEMAS_ENTRYPOINT = os.path.join(os.path.curdir, "schemas", "extension.schema.json")
