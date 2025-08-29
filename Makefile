NPM_ROOT = ./node_modules
STATIC_DIR = src/lemur/static/app
SHELL=/bin/bash
USER := $(shell whoami)

develop: update-submodules setup-git
	@echo "--> Installing dependencies"
ifeq ($(USER), root)
	@echo "WARNING: It looks like you are installing Lemur as root. This is not generally advised."
	npm install --unsafe-perm
else
	npm install
endif
	uv sync --group dev --group test
	node_modules/.bin/gulp build
	node_modules/.bin/gulp package --urlContextPath=$(urlContextPath)
	@echo ""

release:
	@echo "--> Installing dependencies"
ifeq ($(USER), root)
	@echo "WARNING: It looks like you are installing Lemur as root. This is not generally advised."
	npm install --unsafe-perm
else
	npm install
endif
	uv sync
	node_modules/.bin/gulp build
	node_modules/.bin/gulp package --urlContextPath=$(urlContextPath)
	@echo ""

dev-docs:
	uv sync --group docs

reset-db:
	@echo "--> Dropping existing 'lemur' database"
	dropdb lemur || true
	@echo "--> Creating 'lemur' database"
	createdb -E utf-8 lemur
	@echo "--> Enabling pg_trgm extension"
	psql lemur -c "create extension IF NOT EXISTS pg_trgm;"
	@echo "--> Applying migrations"
	cd lemur && lemur db upgrade

setup-git:
	@echo "--> Installing git hooks"
	if [[ -d .git/hooks && -d hooks ]]; then \
		git config branch.autosetuprebase always; \
		cd .git/hooks && ln -sf ../../hooks/* ./; \
	fi
	@echo ""

clean:
	@echo "--> Cleaning static cache"
	${NPM_ROOT}/.bin/gulp clean
	@echo "--> Cleaning pyc files"
	find . -name "*.pyc" -delete
	@echo ""

test: develop lint test-python

testloop: develop
	uv add pytest-xdist
	uv run coverage run --source lemur -m pytest

test-cli:
	@echo "--> Testing CLI"
	rm -rf test_cli
	mkdir test_cli
	cd test_cli && uv run lemur create_config -c ./test.conf > /dev/null
	cd test_cli && uv run lemur -c ./test.conf db upgrade > /dev/null
	cd test_cli && uv run lemur -c ./test.conf help 2>&1 | grep start > /dev/null
	rm -r test_cli
	@echo ""

test-js:
	@echo "--> Running JavaScript tests"
	npm test
	@echo ""

test-python:
	@echo "--> Running Python tests"
	uv run coverage run --source lemur -m pytest
	uv run coverage xml
	@echo ""

lint: lint-python lint-js

lint-python:
	@echo "--> Linting Python files"
	uv run flake8 lemur
	uv run mypy  # scan the directory specified in mypy.ini
	@echo ""

lint-js:
	@echo "--> Linting JavaScript files"
	npm run lint
	@echo ""

coverage: develop
	uv run coverage run --source=lemur -m pytest
	uv run coverage html

publish:
	uv build
	uv publish

up-reqs:
	@echo "--> Updating Python requirements"
	uv lock --upgrade
	@echo "--> Done updating Python requirements"
	@echo "--> Installing new dependencies"
	uv sync --all-groups
	@echo "--> Done installing new dependencies"
	@echo ""

# Execute with make checkout-pr pr=<pr number>
checkout-pr:
	git fetch upstream pull/$(pr)/head:pr-$(pr)


.PHONY: develop dev-postgres dev-docs setup-git build clean update-submodules test testloop test-cli test-js test-python lint lint-python lint-js coverage publish release
