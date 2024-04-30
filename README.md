# dt-cli — Dynatrace developer's toolbox

Dynatrace CLI is a command line utility that assists in signing, building and uploading
extensions for Dynatrace Extension Framework 2.0.

<p>
  <a href="https://pypi.org/project/dt-cli/"><img alt="PyPI" src="https://img.shields.io/pypi/v/dt-cli?color=blue&logo=python&logoColor=white"></a>
  <a href="https://pypi.org/project/dt-cli/"><img alt="PyPI - Python Version" src="https://img.shields.io/pypi/pyversions/dt-cli?logo=python&logoColor=white"></a>
  <a href="https://github.com/dynatrace-oss/dt-cli/actions/workflows/built-test-release.yml"><img alt="GitHub Workflow Status (main branch)" src="https://img.shields.io/github/actions/workflow/status/dynatrace-oss/dt-cli/test.yml?branch=main&logo=github"></a>
</p>

## Features

* Work with Extensions 2.0
  * Build and sign extensions from source
  * Generate CA certificates for development
  * Generate development certificates for extension signing
  * Validate and upload extension to Dynatrace
* *(planned) Perform various API requests from command line*

## FAQ

**What's the difference between monaco and dt-cli?**

* [Monaco](https://github.com/Dynatrace/dynatrace-configuration-as-code) is a **mon**itoring configuration **a**s **co**de solution that allows you to configure Dynatrace environment using GitOps approach. It follows a declarative approach: define what you need and the tool will ensure the correct configuration.
* `dt` command line, on the other hand, is a tool for performing imperative step-by-step configuration. You explicitly invoke commands to modify the state.

## Installation

```shell
pip install dt-cli
```

## Usage

1. *(optional) If you don't already have a developer certificate*
           
   1. Generate CA key and certificate

      ```shell
      $ dt ext genca
      CA private key passphrase []: 
      Repeat for confirmation: 
      Generating CA...

      Wrote CA private key: ./ca.key
      Wrote CA certificate: ./ca.pem
      ```

   1. Generate developer key and certificate from the CA

      ```shell
      $ dt ext generate-developer-pem --ca-crt ca.pem --ca-key ca.key -o dev.pem
      Name: Ext
      Loading CA private key ca.key
      Loading CA certificate ca.pem
      Generating developer certificate...
      Wrote developer certificate: dev.pem
      Wrote developer private key: dev.pem
      ```

1. Upload your CA certificate to the Dynatrace credential vault

   See: [Add your root certificate to the Dynatrace credential vault](https://www.dynatrace.com/support/help/extend-dynatrace/extensions20/sign-extension/#add-your-root-certificate-to-the-dynatrace-credential-vault)

1. Upload your CA certificate to OneAgent or ActiveGate hosts that will run your extension

   See: [Uplaod your root certificate to OneAgent or ActiveGate](https://docs.dynatrace.com/docs/extend-dynatrace/extensions20/sign-extension#upload)

1. Build and sign the extension

   ```shell
   $ dt ext assemble
   Building extension.zip from extension/
   Adding file: extension/dashboards/overview_dashboard.json as dashboards/overview_dashboard.json
   Adding file: extension/extension.yaml as extension.yaml
   Adding file: extension/activationSchema.json as activationSchema.json

   $ dt ext sign --key dev.pem
   Successfully signed the extension bundle at bundle.zip
   ```

1. *(optional) Validate the assembled and signed bundle with your Dynatrace tenant*

   ```shell
   $ dt ext validate bundle.zip --tenant-url https://<tenantid>.live.dynatrace.com --api-token <token>
   Extension validation successful!
   ```

1. Upload the extension to your Dynatrace tenant

   ```shell
   $ dt ext upload bundle.zip --tenant-url https://<tenantid>.live.dynatrace.com --api-token <token>
   Extension upload successful!
   ```

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