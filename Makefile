# Phase 1 pipeline shortcuts.
PYTHON ?= python3
VENV   ?= .venv
PY     := $(VENV)/bin/python

.PHONY: help venv install dataset train evaluate all testbed test clean

help:
	@echo "make install    install dependencies into $(VENV)"
	@echo "make dataset    generate the synthetic SSRF dataset"
	@echo "make train      train the three detection models"
	@echo "make evaluate   evaluate models and write reports/"
	@echo "make all        dataset + train + evaluate"
	@echo "make testbed    run the vulnerable app and simulated internals"
	@echo "make test       run the test suite"
	@echo "make clean      remove generated artifacts"

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

dataset:
	$(PY) -m mlwsg generate-dataset

train:
	$(PY) -m mlwsg train

evaluate:
	$(PY) -m mlwsg evaluate

all:
	$(PY) -m mlwsg all

testbed:
	$(PY) -m mlwsg testbed

test:
	$(PY) -m pytest

clean:
	rm -rf artifacts/models/*.joblib artifacts/models/*.json reports/*.md reports/*.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
