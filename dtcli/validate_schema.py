import json
import pathlib
from pathlib import Path
from typing import Any, List, Union, Callable

from jsonschema import Draft202012Validator, Validator, ValidationError

from referencing import Registry, Resource

import yaml


YamlAST = Union[yaml.ScalarNode, yaml.SequenceNode, yaml.MappingNode]


def backtrack_yaml_location(path: List[Union[int, str]], ast: YamlAST) -> yaml.error.Mark:
    """
    Go through the json-path in input file and returns location line and column.

    Schema validator doesn't know which line and column the error was on, since it operates
    at AST level without retaining source maps.
    """
    if not path:
        return ast.start_mark

    chunk, *rest = path

    if isinstance(chunk, str):
        key_value_pairs = ast.value
        for k, v in key_value_pairs:
            assert isinstance(k, yaml.ScalarNode), "keys are scalar nodes"
            if k.value == chunk:
                return backtrack_yaml_location(rest, v)
    elif isinstance(chunk, int):
        v = ast.value[chunk]
        return backtrack_yaml_location(rest, v)
    else:
        assert 0, "unreachable switch branch"


def remove_unsupported_regex_patterns(data: Any) -> dict:
    if isinstance(data, dict):
        cleanedup_dict = {
            k: remove_unsupported_regex_patterns(v) for k, v in data.items()
            # if not (k == "pattern" and isinstance(v, str) and r"\\p" in v)
            if not (k == "pattern" and isinstance(v, str) and r"\p" in v)
        }
        return cleanedup_dict
    elif isinstance(data, list):
        cleanedup_list = [
            remove_unsupported_regex_patterns(i) for i in data
        ]
        return cleanedup_list
    else:
        return data


def validate_schema(extension_yaml_path: Path, extension_schema_path: Path, warn: Callable[[str], None]) -> list:
    schema_dir_path = pathlib.Path(extension_schema_path).parent

    with open(extension_yaml_path, "r") as yaml_in:
        instance = yaml.safe_load(yaml_in)

    with open(extension_schema_path) as f:
        schema_data = json.load(f)
        cleanedup_schema_data = remove_unsupported_regex_patterns(schema_data)

    subschema_paths = [
        p for p in schema_dir_path.iterdir() if p.is_file() and extension_schema_path.absolute() != p.absolute()
    ]

    resources: list[tuple[str, dict]] = []
    for c in subschema_paths:
        try:
            with open(c) as f:
                subschema_data = json.load(f)
        except json.decoder.JSONDecodeError:
            warn(f"skipping subschema {c}, malformed json")
        else:
            cleanedup_subschema_data = remove_unsupported_regex_patterns(subschema_data)
            subschema_uri = cleanedup_subschema_data["$id"]
            subschema = Resource.from_contents(cleanedup_subschema_data)
            resources.append((subschema_uri, subschema))

    registry = Registry().with_resources(resources)
    validator: Validator = Draft202012Validator(
        cleanedup_schema_data,
        registry=registry,
    )

    with open(extension_yaml_path, "r") as f:
        file = yaml.compose(f)

    def process_validation_error(error: ValidationError):
        err_loc = backtrack_yaml_location(error.absolute_path, file)

        # TODO: add typo finder for some cases - like enum mismatch
        return {
            "line": err_loc.line,
            "column": err_loc.column,
            "path": ".".join(map(str, error.absolute_path)),
            "cause": error.message
        }

    detected_errors = list(validator.iter_errors(instance))
    errors_info: list[dict] = []
    for err in detected_errors:
        error_info = process_validation_error(err)
        errors_info.append(error_info)

    return errors_info
