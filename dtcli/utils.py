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

import os.path
import re


class ExtensionBuildError(Exception):
    pass


class KeyGenerationError(Exception):
    pass

def require_extension_name_valid(extension_name):
    extension_name_regex = re.compile("^custom:(?!\\.)(?!.*\\.\\.)(?!.*\\.$)[a-z0-9-_\\.]+$")
    if not extension_name_regex.match(extension_name):
        print("%s doesn't satisfy extension naming format, aborting!" % extension_name)
        raise ExtensionBuildError()

def check_file_exists(file_path, exception_cls=ExtensionBuildError, warn_overwrite=True):
    """Returns True and prints a message if file under given path exists and is a real file.
    In case the path represents a directory, exception given in the exception_cls parameter will be thrown.
    In case there's no file under the given path returns False.
    """
    if os.path.exists(file_path):
        require_is_not_dir(file_path, exception_cls)
        if warn_overwrite:
            print("%s file already exists, it will be overwritten!" % file_path)
        return True
    return False


def require_file_exists(file_path):
    if not os.path.exists(file_path):
        print("%s doesn't exist, aborting!" % file_path)
        raise ExtensionBuildError()


def require_dir_exists(dir_path):
    if not os.path.isdir(dir_path):
        print("%s is not a directory, aborting!" % dir_path)
        raise ExtensionBuildError()


def require_is_not_dir(file_path, exception_cls=ExtensionBuildError):
    if os.path.isdir(file_path):
        print("%s is a directory, aborting!" % file_path)
        raise exception_cls()


def remove_files(file_paths):
    for file_path in file_paths:
        try:
            os.remove(file_path)
        except:
            print("Failed to remove %s" % file_path)
