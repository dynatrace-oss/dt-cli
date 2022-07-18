setup:  ## prepare the environment
	poetry install

lint:
	poetry run flake8 dtcli/scripts
	# TODO: reenable those pesky warnings in .flake8
	# TODO: run for entire source code
	# TODO: bump CI
	#poetry run pytest --mypy dtcli --strict
	# TODO: enable
	# TODO: bump CI

test:
	poetry run pytest -x

bump-version: ## bumps version (sepecified into VERSION)
	poetry run bump2version --no-tag --no-commit --new-version $(VERSION) whatever

.PHONY: help init
init: ## one time setup
	direnv allow .

help: ## print this message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.DEFAULT_GOAL := help
