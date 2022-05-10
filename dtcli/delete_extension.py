import json
from collections import defaultdict
from typing import Dict, Set, Optional, List
from pathlib import Path


# from src.api import DynatraceAPIClient
# from api import DynatraceAPIClient
from dtcli.api import DynatraceAPIClient

class State:
    def __init__(self, d):
        self.d = d

    def __getitem__(self,key):
        return self.d[key]

    def __contains__(self, key):
        return key in self.d

    def __str__(self):
        return str(self.d)

    def versions(self, extension_fqdn, exclude: Optional[Set[str]] = None) -> List[str]:
        if exclude is None:
            exclude = set()

        all_versions: Set[str] = set(self[extension_fqdn].keys())

        return list(sorted(all_versions - exclude))

    def as_dict(self):
        return self.d

def acquire_state(client: DynatraceAPIClient) -> State:
    extensions_listing = list(map(lambda e: e["extensionName"], client.acquire_extensions()))

    extensions_data = []
    for e in extensions_listing:
        _extensions_data = client.acquire_extension_versions(e)
        extensions_data += _extensions_data

    extensions = defaultdict(dict)
    for e in extensions_data:
        name, version = e["extensionName"], e["version"]
        extensions[name][version] = {"monitoring_configurations": []}

    for extension in extensions_listing:
        environment_configuration = client.acquire_environment_configuration(extension)
        monitoring_configurations = client.acquire_monitoring_configurations(extension)

        if environment_configuration:
            extensions[extension][environment_configuration["version"]]["environment_configuration"] = environment_configuration
            for mc in monitoring_configurations:
                extensions[extension][mc["value"]["version"]]["monitoring_configurations"].append(mc)

    s = State(extensions)
    return s

def wipe_extension_version(client, state, extension_fqdn: str, version: str):
    assert extension_fqdn in state
    if version not in state[extension_fqdn]:
        return

    # TODO: when refactoring to command pattern remember that the order and groups matter
    for mc in state[extension_fqdn][version]["monitoring_configurations"]:
        client.delete_monitoring_configuration(extension_fqdn, mc["objectId"])
    if "environment_configuration" in state[extension_fqdn][version]:
        # TODO: dehardcode it
        there_are_other_mcs = False

        if there_are_other_mcs:
            # this will be a pain to sensibly parallelize, so... for now don't run this thing on the same fqdn simultaneously
            target_version = state.versions(extension_fqdn, exclude={version})[-1]
            client.point_environment_configuration_to(extension_fqdn, target_version)
        else:
            client.delete_environment_configuration(extension_fqdn)

    client.delete_extension(extension_fqdn, version)

def wipe_extension(client, state, extension_fqdn: str):
    if extension_fqdn not in state:
        return

    for version in state[extension_fqdn]:
        # need to do this as environment configuration can be assigned to any extension version
        # TODO: refactor this to first delete the extension with environment configuration and don't regenerate state!
        wipe_extension_version(client, state, extension_fqdn, version)
        state = acquire_state(client)


# TODO: split arguments that will be usefull with all commands (tenant, secrets)
def wipe_single_version(fqdn: str, version: str, tenant: str, token_path: str):
    """Wipe single extension version

    Example: ... 'com.dynatrace.palo-alto.generic' '0.1.5' --tenant lwp00649 --secrets-path ./secrets
    """
    with open(token_path) as f:
        token = f.readlines()[0].rstrip()

    # client = DynatraceAPIClient.from_dev_tenant(tenant, secrets)
    client = DynatraceAPIClient.from_tenant_url(tenant, token)
    state = acquire_state(client)
    print(state)

    wipe_extension_version(client, state, fqdn, version)

def wipe(fqdn: str, tenant: str, token: str):
    token = token
    # TODO: move client creation further up the chain
    # client = DynatraceAPIClient.from_dev_tenant(tenant, secrets)
    client = DynatraceAPIClient.from_tenant_url(tenant, token)
    state = acquire_state(client)

    wipe_extension(client, state, fqdn)

def state(tenant: str, token: str):
    token = token
    # client = DynatraceAPIClient.from_dev_tenant(tenant, secrets)
    client = DynatraceAPIClient.from_tenant_url(tenant, token)
    state = acquire_state(client)
    print(json.dumps(state.as_dict()))

