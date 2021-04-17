# dt-cli — Dynatrace developer's toolbox

Dynatrace CLI is a command line utility that assists in developing, signing,
and building extensions for Dynatrace Extension Framework 2.0.

<p>
  <a href="https://pypi.org/project/dt-cli/"><img alt="PyPI" src="https://img.shields.io/pypi/v/dt-cli?color=blue"></a>
  <a href=""><img alt="GitHub Workflow Status" src="https://img.shields.io/github/workflow/status/dynatrace-oss/dt-cli/build-test-release?label=Build&logo=github"></a>
</p>


`dt-cli` is currently in **ALPHA**. But it's evolving quickly with new
features for extension development and cluster management to be added soon.

### Features

* Build and sign extensions from source
* Generate development certificates for extension signing
* Generate CA certificates for development

## Installation

```shell
pip install dt-cli
```

## Usage

Currently there are three basic commands available for working with extensions.
Extension subcommand has two aliases for convenience: `dt ext` or `dt extensions`.

* `dt extension genca`

  generates CA root certificate and key, required to generate developer certificates
  and for extension validation. The file containing the certificate (`ca.cert` is
  the deafult name) needs to be placed on ActiveGates and monitored hosts that will
  be executing extensions.

  ```shell
  Usage: dt extension genca [OPTIONS]

    creates CA key and certificate, needed to create developer certificate
    used for extension signing

    Options:
    --ca-cert TEXT  CA certificate. Default: ./ca.crt
    --ca-key TEXT   CA key. Default: ./ca.key
    -h, --help      Show this message and exit.
  ```

* `dt extension gendevcert`

  generates a developer certificate used for signing extensions. Please note that
  there may be multiple developer certificates coming from a single root
  certificate. It's up to your organization to manage them.

  ```shell
  Usage: dt extension gendevcert [OPTIONS]

    creates developer key and certificate used for extension signing

    Options:
    --ca-cert TEXT   CA certificate. Default: ./ca.crt
    --ca-key TEXT    CA key. Default: ./ca.key
    --dev-cert TEXT  Developer certificate. Default: ./developer.crt
    --dev-key TEXT   Developer key. Default: ./developer.key
    -h, --help       Show this message and exit.
  ```

* `dt extension build`
  builds distributable extension file from a given directory containing extension files
  (`./extension` by default). The extension will be signed with a developer certificate and key.

  ```shell
  Usage: dt extension build [OPTIONS]

    builds extension file from the given extension directory (`extension' in
    current dir. is the default)

    Options:
    --extension-directory TEXT  Directory where extension files are. Default:
                                ./extension

    --target-directory TEXT     Directory where extension package should be
                                written. Default: .

    --certificate TEXT          Certificate used for signing. Default:
                                ./developer.crt

    --private-key TEXT          Private key used for signing. Default:
                                ./developer.key

    --keep-intermediate-files   Do not delete the signature and `extension.zip'
                                files after building extension archive

    -h, --help                  Show this message and exit.
  ```

## Development

This tool requires Python 3.8+ and is build with [poetry](https://python-poetry.org/).
Before starting, make sure you have a dedicated [virtual environment](https://docs.python.org/3/library/venv.html)
for working with this project. Create your virtual environment in project directory:

```shell
python -m venv env
````

Activate it before proceeding:

```shell
source ./env/bin/activate
```

Install `poetry`:

```shell
$ pip install poetry
```

Now you can build the project and get the wheel file:

```shell
$(env) poetry build
```

The resulting wheel file can be found in the `dist` folder, e.g. `./dist/dtcli-0.0.1-py3-none-any.whl`

If you have a separate environment where `dtcli` should be available, you should install the  wheel file there. Simply run the following command:

```shell
$ pip install dt_cli-0.0.1-py3-none-any.whl
```

If you want to start using it in the environment where it was built, you just use this `poetry` command:

```shell
$ poetry install
```

From this moment you can start using the command line tool directly (or from your code, see a dedicated section below):

```shell
$ dt --help
```

Each command contains its own help description, see:

```shell
$ dt ext build --help
```

## Testing

Run `pytest` tests

```shell
poetry run pytest --flake8
```

Run `mypy` tests

```shell
poetry run pytest --mypy dtcli --strict
```

Run test coverage report

```shell
poetry run pytest --cov . --cov-report html
```

## Using `dt-cli` from your Python code

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
    keep_intermediate_files=False,
)
```

## Contributions

You are welcome to contribute using Pull Requests to the respective repositories. Before contributing, please read our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

`dt-cli` is an Open Source Project. Please see [LICENSE](LICENSE) for more information.