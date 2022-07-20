import json
import pathlib
from pathlib import Path
from typing import List, Union, Callable

import jsonschema

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


def validate_schema(instance_object: Path, schema_entrypoint: Path, warn: Callable[[str], None]) -> list:
    subschemas_path = pathlib.Path(schema_entrypoint).parent

    with open(instance_object, "r") as yaml_in:
        instance = yaml.safe_load(yaml_in)

    with open(schema_entrypoint) as f:
        s = json.load(f)

    schema_store = {}
    for subschema_candidate in filter(lambda f: f.is_file, pathlib.Path(subschemas_path).iterdir()):
        try:
            with open(subschema_candidate) as f:
                sub = json.load(f)
        except json.decoder.JSONDecodeError:
            warn(f"skipping subschema {subschema_candidate}, malformed json")
            # print(f"skipping subschema {subschema_candidate}, malformed json", file=sys.stderr)
        else:
            sub_id = sub["$id"]
            schema_store[sub_id] = sub

    resolver = jsonschema.validators.RefResolver.from_schema(s, store=schema_store)

    validator_cls = jsonschema.validators.validator_for(s)
    validator_cls.check_schema(s)  # against META_SCHEMA
    validator = validator_cls(s, resolver=resolver)

    with open(instance_object, "r") as f:
        file = yaml.compose(f)

    def process_validation_error(error):
        err_loc = backtrack_yaml_location(error.absolute_path, file)

        # TODO: add typo finder for some cases - like enum mismatch
        return {
            "line": err_loc.line,
            "column": err_loc.column,
            "path": ".".join(map(str, error.absolute_path)),
            "cause": error.message
        }

    return list(map(process_validation_error, validator.iter_errors(instance)))
