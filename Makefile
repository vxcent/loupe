.PHONY: setup smoke run clean

setup:
	pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	@echo "edit .env to add TOGETHER_API_KEY"

smoke:          ## offline plumbing demo (no API key needed)
	python eval.py --backend mock

run:            ## real run on the fixture via Together AI
	python eval.py --backend together

clean:
	rm -f results/*.csv results/*.png
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
