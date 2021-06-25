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

import pytest
from dtcli import utils

def test_require_extension_name_valid():
    utils.require_extension_name_valid("custom:e")
    utils.require_extension_name_valid("custom:some.test.ext")
    utils.require_extension_name_valid("custom:some_simple.test.ext-1")
    utils.require_extension_name_valid("custom:_some_simple_test_extension")
    utils.require_extension_name_valid("custom:-some-simple.test.ext_1_")

def test_require_extension_name_valid_negative():
    with pytest.raises(utils.ExtensionBuildError):
        utils.require_extension_name_valid("some.test.ext")
    with pytest.raises(utils.ExtensionBuildError):
        utils.require_extension_name_valid("custom:")
    with pytest.raises(utils.ExtensionBuildError):
        utils.require_extension_name_valid("custom:.some.test.ext.")
    with pytest.raises(utils.ExtensionBuildError):
        utils.require_extension_name_valid("custom:som:e.t/est.e$xt")
    with pytest.raises(utils.ExtensionBuildError):
        utils.require_extension_name_valid("custom:SOME.test.ext")
    with pytest.raises(utils.ExtensionBuildError):
        utils.require_extension_name_valid("custom:SOME123.test.ext")
    with pytest.raises(utils.ExtensionBuildError):
        utils.require_extension_name_valid("custom:\u0194test,ext")
