# dt-cli — Dynatrace developer's toolbox

Dynatrace CLI is a command line utility that assists in signing, building and uploading
extensions for Dynatrace Extension Framework 2.0.

<p>
  <a href="https://pypi.org/project/dt-cli/"><img alt="PyPI" src="https://img.shields.io/pypi/v/dt-cli?color=blue&logo=python&logoColor=white"></a>
  <a href="https://pypi.org/project/dt-cli/"><img alt="PyPI - Python Version" src="https://img.shields.io/pypi/pyversions/dt-cli?logo=python&logoColor=white"></a>
  <a href="https://github.com/dynatrace-oss/dt-cli/actions/workflows/built-test-release.yml"><img alt="GitHub Workflow Status (main branch)" src="https://img.shields.io/github/workflow/status/dynatrace-oss/dt-cli/Build%20Test%20Release/main?logo=github"></a>
</p>


### Features

* Build and sign extensions from source
* Generate development certificates for extension signing
* Generate CA certificates for development
* Validate and upload extension to Dynatrace Extension Framework 2.0.

## Installation

```shell
pip install dt-cli
```

## Usage

1. Generate certificates
```sh
  dt extension gencerts
```
2. Upload your `ca.pem` certificate to the Dynatrace credential vault

See: [Add your root certificate to the Dynatrace credential vault](https://www.dynatrace.com/support/help/extend-dynatrace/extensions20/sign-extension/#add-your-root-certificate-to-the-dynatrace-credential-vault)

3. Build and sign, then upload extension
```sh
  dt extension build
  dt extension upload
```
Use `dt extension --help` to learn more

4. Download extension schemas
```sh
  dt extension schemas
```
_API permissions needed: `extensions.read`_

This script should only be needed once, whenever schema files are missing or you want to target a different version than what you already have. It does the following:
* Downloads all the extension schema files of a specific version
* Schemas are downloaded to `schemas` folder

5. Wipes out extension from Dynatrace Cluster
```sh
  dt extension delete
```
Use `dt extension --help` to learn more


## Using dt-cli from your Python code

You may want to use some commands implemented by `dt-cli` directly in your Python code, e.g. to automatically sign your extension in a CI environment.
Here's an example of building an extension programatically, it assumes `dtcli` package is already installed and available in your working environment.


```python
from dtcli import building


building.build_extension(
    extension_dir_path = './extension',
    extension_zip_path = './extension.zip',
    extension_zip_sig_path = './extension.zip.sig',
    target_dir_path = './dist',
    certificate_file_path = './developer.crt',
    private_key_file_path = './developer.key',
    dev_passphrase=None,
    keep_intermediate_files=False,
)
```

## Development

See our [CONTRIBUTING](CONTRIBUTING.md) guidelines and instructions.

## Contributions

You are welcome to contribute using Pull Requests to the respective
repository. Before contributing, please read our
[Code of Conduct](https://github.com/dynatrace-oss/dt-cli/blob/main/CODE_OF_CONDUCT.md).

## License

`dt-cli` is an Open Source Project. Please see
[LICENSE](https://github.com/dynatrace-oss/dt-cli/blob/main/LICENSE) for more information.