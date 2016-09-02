NPM_ROOT = ./node_modules
STATIC_DIR = src/lemur/static/app

develop: update-submodules setup-git
	@echo "--> Installing dependencies"
	npm install
	pip install "setuptools>=0.9.8"
	# order matters here, base package must install first
	pip install -e .
	pip install "file://`pwd`#egg=lemur[dev]"
	pip install "file://`pwd`#egg=lemur[tests]"
	node_modules/.bin/gulp build
	node_modules/.bin/gulp package
	@echo ""

dev-docs:
	pip install -r docs/requirements.txt

reset-db:
	@echo "--> Dropping existing 'lemur' database"
	dropdb lemur || true
	@echo "--> Creating 'lemur' database"
	createdb -E utf-8 lemur
	@echo "--> Applying migrations"
	lemur db upgrade

setup-git:
	@echo "--> Installing git hooks"
	git config branch.autosetuprebase always
	cd .git/hooks && ln -sf ../../hooks/* ./
	@echo ""

clean:
	@echo "--> Cleaning static cache"
	${NPM_ROOT}/.bin/gulp clean
	@echo "--> Cleaning pyc files"
	find . -name "*.pyc" -delete
	@echo ""

test: develop lint test-python

testloop: develop
	pip install pytest-xdist
	py.test tests -f

test-cli:
	@echo "--> Testing CLI"
	rm -rf test_cli
	mkdir test_cli
	cd test_cli && lemur create_config -c ./test.conf > /dev/null
	cd test_cli && lemur -c ./test.conf db upgrade > /dev/null
	cd test_cli && lemur -c ./test.conf help 2>&1 | grep start > /dev/null
	rm -r test_cli
	@echo ""

test-js:
	@echo "--> Running JavaScript tests"
	npm test
	@echo ""

test-python:
	@echo "--> Running Python tests"
	py.test -v || exit 1
	@echo ""

lint: lint-python lint-js

lint-python:
	@echo "--> Linting Python files"
	PYFLAKES_NODOCTEST=1 flake8 lemur
	@echo ""

lint-js:
	@echo "--> Linting JavaScript files"
	npm run lint
	@echo ""

coverage: develop
	coverage run --source=lemur -m py.test
	coverage html

publish:
	python setup.py sdist bdist_wheel upload

OS = $(shell uname -s | tr LD ld)
/usr/local/bin/rocker:
	curl -SL https://github.com/grammarly/rocker/releases/download/1.3.0/rocker_$(OS)_amd64.tar.gz | sudo tar -xzC /usr/local/bin 
	sudo chmod +x /usr/local/bin/rocker

.docker_db_running:
	docker run -d --name lemur_postgres postgres
	@echo "--> Waiting for initdb"; sleep 5
	docker exec lemur_postgres psql -U postgres --command "CREATE DATABASE lemur;"
	docker exec lemur_postgres psql -U postgres --command "CREATE USER lemur WITH PASSWORD 'lemur';"
	docker exec lemur_postgres psql -U postgres --command "GRANT ALL PRIVILEGES ON DATABASE lemur to lemur;"
	touch .docker_db_running

docker: /usr/local/bin/rocker .docker_db_running
	rocker build .
	docker run -p 8000:80 --rm -it --link lemur_postgres:postgres netflix/lemur || :
	@echo "run:"
	@echo "   docker rm -fv lemur_postgres && rm -f .docker_db_running"
	@echo "if you want to discard the database"

.PHONY: develop dev-postgres dev-docs setup-git build clean update-submodules test testloop test-cli test-js test-python lint lint-python lint-js coverage publish docker
