ROOT_DIR        := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
MODULE_NAME     := $(notdir $(patsubst %/,%,$(ROOT_DIR)))
SHELL		:= /bin/bash

all:
	@echo 'Available make targets:'
	@grep '^[^#[:space:]].*:' Makefile

install:
	# Installs as egg
	python setup.py install
	# Installs via pip
	pip install .

build:
	python setup.py build

python-venv: venv
venv:
	$(shell [ -d venv ] || python3 -m venv venv)
	echo "# Run this in your shell to activate:"
	echo "source venv/bin/activate"

.install-test:
		pip install .[test]	
		npm install kinesalite
		touch $@

.flake:
	flake8 setup.py
	flake8 tests/*.py
	flake8 $(MODULE_NAME)/*.py

watch-test:
	# Watches for changes and re-test automatically
	# we use this wrapper because our test target allows for more tests
	# than ptw's builting pytest, notably flake8 tests
	ptw --runner "make test"

test: tests
tests: .install-test .flake
	PATH=$(PATH):$(shell npm bin) \
	python setup.py test

.PHONY test-tox:
test-tox: .flake
	PATH=$(PATH):$(shell npm bin) \
	tox -p all --parallel-live

.install-perf-test:
	pip3 install pytest-benchmark
	pip3 install pygal pygaljs 
	pip3 install pytest-benchmark[histogram]

.PHONY 	perf-test:
perf-test:
	py.test $(ROOT_DIR)/integration_tests --capture=no --benchmark-autosave --benchmark-histogram

clean:
	rm -rf venv
	rm -rf __pycache__
	rm -rf *.egg-info
	rm -rf .eggs
	rm -rf build
	rm -rf dist
	rm -rf .install-test
	rm -rf node_modules

.PHONY: test tests clean all install
