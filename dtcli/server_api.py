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

import requests

from . import utils as dtcliutils


def validate(extension_zip_file, tenant_url, api_token):
    url = f"{tenant_url}/api/v2/extensions?validateOnly=true"

    with open(extension_zip_file, "rb") as extzf:
        headers = {"Accept": "application/json; charset=utf-8", "Authorization": f"Api-Token {api_token}"}
        try:
            response = requests.post(
                url, files={"file": (extension_zip_file, extzf, "application/zip")}, headers=headers
            )
            response.raise_for_status()
            print(f"Extension validation successful!")
        except requests.exceptions.HTTPError as e:
            print(f"Extension validation failed!")
            raise dtcliutils.ExtensionValidationError(response.text)


def upload(extension_zip_file, tenant_url, api_token):
    url = f"{tenant_url}/api/v2/extensions"

    with open(extension_zip_file, "rb") as extzf:
        headers = {"Accept": "application/json; charset=utf-8", "Authorization": f"Api-Token {api_token}"}
        try:
            response = requests.post(
                url, files={"file": (extension_zip_file, extzf, "application/zip")}, headers=headers
            )
            response.raise_for_status()
            print(f"Extension upload successful!")
        except requests.exceptions.HTTPError as e:
            print(f"Extension upload failed!")
            raise dtcliutils.ExtensionValidationError(response.text)
