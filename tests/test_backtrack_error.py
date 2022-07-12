import yaml
from yaml import MappingNode, ScalarNode, SequenceNode

from dtcli.validate_schema import backtrack_yaml_location


def test_simple(mocker):
    m = mocker.Mock()
    assert backtrack_yaml_location([], ScalarNode(value="ble", tag=None, start_mark=m)) == m


def test_complex_select_mapping(mocker):
    m = mocker.Mock()
    ast = MappingNode(tag='', value=[
        (ScalarNode(tag='k', value='a'),
         None),
        (ScalarNode(tag='key', value='b'),
         ScalarNode(tag="v", value=None, start_mark=m))
    ])
    assert backtrack_yaml_location(["b"], ast) == m


def test_complex_select_sequence(mocker):
    m = mocker.Mock()
    ast = SequenceNode(tag="", value=[
        ScalarNode(tag="", value="scalar"),
        ScalarNode(tag="", value="sequence", start_mark=m),
        ScalarNode(tag="", value="mapping")
    ])
    assert backtrack_yaml_location([1], ast) == m
