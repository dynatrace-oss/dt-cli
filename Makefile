setup:  ## prepare the environment
	poetry install

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
