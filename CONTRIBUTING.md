# Contributing to dt-cli

👍🎉 Thank you for choosing to contribute to dt-cli! 🎉👍

**Table of Contents**

* [Development](#development)
  * [Required tools](#required-tools)
  * [Environment setup](#environment-setup)
    * [With Poetry](#with-poetry)
    * [With Docker](#with-docker)
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

* Set up a virtual environment

  After poetry is installed and proper version of Python is present in the system,
  tell poetry to use the proper version for creation of the virtual environment.

  ```shell
  poetry env use 3.9.5
  ```

  It might be beneficial to have the virtual environment placed right inside the project directory for
  an easier configuration of the syntax highlighting in the IDE. For these purposes, create the virtual
  environment named `.venv` in the root directory of the project. Poetry will automatically pick it up
  and use it as a destination directory for its operations with the venv as described in
  [the docs](https://python-poetry.org/docs/configuration/#virtualenvsin-project).

  ```shell
  python -m venv .venv
  ```

  Now you can install the dependencies specified in `pyproject.toml` and `poetry.lock`
  (frozen versions and hashes of dependencies).

  ```shell
  poetry install
  ```

<a id="with-docker"></a>

#### With Docker

* Copy toml file to ensure cacheability. Bash\Powershell:

  ```shell
  cp pyproject.toml pyproject.toml.mod
  ```
  
* Build the image locally:

  ```shell
  docker build -t dtcli-dev .
  ```

* Run it with root of the repo mounted into `/app` directory:

  ```shell
  docker run --rm -it -v "$(pwd):/app" dtcli-dev bash
  ```

  This will launch an interactive shell into Docker container where you can run all the commands below.

<a id="development-commands"></a>

### Development commands

* Run interactive python shell with syntax highlighting within the virtual environment

  ```shell
  poetry run ipython
  ```

* Run full test suite using MyPy, flake8, Coverage, and pytest:

  ```shell
  poetry run pytest --mypy dtcli --strict --flake8 --cov . --cov-report html
  ```

* Run `pytest` until the first failed test

  ```shell
  poetry run pytest -x
  ```

* Run `dt` command line itself in it's current state within the virtual environment

  ```shell
  poetry run dt --help
  ```

* Bump to the new version using `bump2version` CLI.

  *Note: all changes must be committed*.

  ```shell
  # Here <part> is major (x.0.0), minor (0.x.0), or patch (0.0.x)
  poetry run bump2version patch

  # or
  poetry run bump2version --new-version 1.2.3 <part>
  ```

<a id="development-cycle"></a>

### Development cycle

Every commit and branch name must contain a short word describing the changes that were applied.
Currently, the following set of words is being used:

* `doc`: Changes to the documentation
* `cli`: Command line interface
* `lib`: Improvements to library (reusable and importable) portion of the dt-cli
* `build`: Changes to the build or CI/CD process
* `bug`: Bugfix
* `feat`: New feature
* `lint`: Changes caused by formatting or refactoring performed mainly for styling purposes
* `typing`: Fixes improvements around strong typing
* `tests`: Changes to the set of tests
* `chore`: Anything not falling under the described category but that **needs** to be done

Steps to follow when adding new changes:
  
* Create a new branch for your changes.

  Branch must be related to an existing GitHub issue. The naming convention for the branch is

  ```shell
  # Username is optional but preferrable to be able to quickly filter the branches
  # Issue ID is a number that represents the GitHub issue resolved by this branch.
  # Change subtype is something like: doc
  # Short description is something like: fix typo

  <username>?-<issue id>-<change type>-<short description>

  # Example

  vduseev-12-feat-implement-init-command
  ```

* Run the test suite locally.

  ```shell
  poetry run pytest
  ```

* Put the mention of the GitHub issue ID into the commit message (e.g. `Implements #19`).

  ```text
  feat: Init command

  New command is added to initialize a new extension.

  Implements #12
  ```

* Push new branch to the repo (if you are maintainer) or create a PR from your fork or branch.
* Wait for the pipeline to build and test the changes in the PR.
* PR gets approved and merged into the `main` branch by the reviewers.
* Maintainers wait until enough changes are accumulated in the `main` branch for a new release.
* Maitaner makes a new release
  * Pulls the `main` branch locally
  * Runs all tests to double check
  * Runs `poetry bump2version <part>` to bump the version which creates a new commit and a tag.
  * Pushes the newly versioned `main` branch back to the GitHub using `git push --follow-tags`
  * New tagged push triggers the release of new version to the PyPI.

<a id="development-configuration"></a>

### Development configuration

* `.python-version` tells `pyenv` which Python version to use in the project directory
* `.coveragerc` contains settings that control how test coverage is measured
* `.bumpversion.cfg` controls how version is bumped and how semantics of it work
* `.readthedocs.yml` controls how Sphinx documentation is built on Readthedocs platform
* `pyproject.toml` controls most of the tool settings (instead of the old approach with `setup.cfg`).
* `.github/workflows/*` contains Pipeline settings for GitHub actions.
