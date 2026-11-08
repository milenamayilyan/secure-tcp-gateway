.PHONY: test demo install
install:
	python3 -m pip install -r requirements-dev.txt
test:
	python3 -m pytest -q
demo:
	sudo -E PYTHON=$$(which python3) demo/netns_demo.sh run
