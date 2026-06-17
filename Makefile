.PHONY: setup smoke run owasp-data owasp pollution clean

setup:
	pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	@echo "edit .env to add TOGETHER_API_KEY"

smoke:          ## offline plumbing demo (no API key needed)
	python eval.py --backend mock

run:            ## real run on the fixture via Together AI
	python eval.py --backend together

owasp-data:     ## sparse/shallow checkout of the OWASP Benchmark
	bash scripts/get_owasp.sh

owasp:          ## real learning curve on a 72-case OWASP slice (+ plot)
	python eval.py --backend together --owasp-dir benchmark \
		--limit 72 --shuffle --window 24 --plot --out results/owasp_curve.csv

pollution:      ## deterministic memory-pollution defense matrix (no API key)
	python experiments/pollution.py

gepa:           ## evolve the distiller prompt (GEPA-lite, Together AI)
	python experiments/gepa_distiller.py --owasp-dir benchmark --limit 60 --generations 4

scale:          ## trustworthy multi-seed curve (300 cases x 3 arms x 3 seeds)
	python experiments/scale.py --owasp-dir benchmark --limit 300 --seeds 3 --workers 8

cyber-baseline: ## mini-Cybench: empty-playbook baseline over the grounded suite
	python -m experiments.cyber.run

clean:
	rm -f results/*.csv results/*.png
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
