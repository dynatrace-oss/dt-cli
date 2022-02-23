# Contributing to dt-cli

👍🎉 Thank you for choosing to contribute to dt-cli! 🎉👍

**Table of Contents**

* [Development](#development)
  * [Required tools](#required-tools)
  * [Environment setup](#environment-setup)
    * [With Poetry](#with-poetry)
    * [With Docker](#with-docker)
  * [How to use Poetry](#how-to-use-poetry)
  * [Development commands](#development-commands)
  * [Development cycle](#development-cycle)
  * [Development configuration](#development-configuration)

<a id="development"></a>
## Development

This tool requires Python 3.8+ and is built with [poetry](https://python-poetry.org/).
Before starting, make sure you have a dedicated [virtual environment](https://docs.python.org/3/library/venv.html)
for working with this project.

<a id="required-tools"></a>
### Required tools

You will need Python 3.8+ and `poetry` tool installed on your system.
Alternatively, you can use the Docker image to replicate the environment without having to install anything on your system.

<a id="environment-setup"></a>
### Environment setup

<a id="with-poetry"></a>
#### With Poetry

After poetry is installed and proper version of Python is present in the system,
tell poetry to use the proper version for creation of the virtual environment.

```shell
poetry env use 3.9.5
```

Now you can install the dependencies specified in `pyproject.toml` and `poetry.lock` (frozen versions and hashes of dependencies).

```shell
poetry install
```

<a id="with-docker"></a>
#### With Docker

Build the image locally:

```shell
docker build -t dtcli-dev .
```

Run it with root of the repo mounted into `/app` directory:

```shell
docker run --rm -it -v "$(pwd):/app" dtcli-dev bash
```

This will launch an interactive shell into Docker container where you can run all the commands below.

<a id="how-to-use-poetry"></a>
### How to use Poetry

Installing all dependencies from the `pyproject.toml` and the `poetry.lock`.

```shell
poetry install
```

Run any command within the virtual environment:

```shell
poetry run <command>
```

Get info about the virtual environment

```shell
poetry env info
```

Uninstalling the virtual environment directory completely

```shell
rm -rf $(poetry env info -p)
```

Add new dependency package. For example, Dynatrace's python API:

```shell
poetry add dt
```

Add new development dependency. Will not be installed on the user system, only for development.

```shell
poetry add --dev black
```

Remove an existing dependency

```shell
poetry remove ipython
```

<a id="development-commands"></a>
### Development commands

Run interactive python shell with syntax highlighting within the virtual environment

```shell
poetry run ipython
```

Run full test suite using MyPy, flake8, Coverage, and pytest:

```shell
poetry run pytest --mypy dtcli --strict --flake8 --cov . --cov-report html
```

Run `pytest` until the first failed test

```shell
poetry run pytest -x
```

Run `dt` command line itself in it's current state within the virtual environment

```shell
poetry run dt --help
```

Bump to the new version using `bump2version` CLI.
*Note: all changes must be committed*.

```shell
# Where <part> is major (x.0.0), minor (0.x.0), or patch (0.0.x)
poetry run bump2version patch
# or
poetry run bump2version --new-version 1.2.3 <part>
```

<a id="development-cycle"></a>
### Development cycle

1. Create a new branch for a new feature or to fix a bug.
1. Make required changes.
1. Test locally.
1. Commit them with mentioning the GitHub issue ID (e.g. `Implements #19`).
1. Push new branch to the repo (if you are maintainer) or create a PR from your fork.
1. Wait for the pipeline to built and test the changes in PR.
1. PR gets approved and merged into the `main` branch.
1. Maintainers wait until enough changes are accumulated in the `main` branch for a new release.
1. Maintainer pulls the `main` branch and runs `poetry bump2version <part>`
   which creates a new commit and a tag.
1. Maintainer then pushes the newly versioned `main` branch back to the GitHub using `git push --follow-tags`
1. New tagged push triggers the release of new version to the PyPI.

<a id="development-configuration"></a>
### Development configuration

1. `.coveragerc` contains settings that control how test coverage is measured
1. `.bumpversion.cfg` controls how version is bumped and how semantics of it work
1. `.readthedocs.yml` controls how Sphinx documentation is built on Readthedocs platform
1. `pyproject.toml` controls most of the tool settings (instead of the old approach with `setup.cfg`).
1. `.github/workflows/*` contains Pipeline settings for GitHub actions.
