# Developer guardrails for the recon kit. See tools/check.sh for the logic.
# Usage: make check | make lint | make smoke | make syntax
.PHONY: check lint smoke syntax help

help:
	@echo "make check   - syntax + shellcheck + smoke (everything)"
	@echo "make syntax  - bash -n on every script"
	@echo "make lint    - shellcheck every script"
	@echo "make smoke   - list every phase's sub-tasks in both modes"

check:
	@bash tools/check.sh all

syntax:
	@bash tools/check.sh syntax

lint:
	@bash tools/check.sh lint

smoke:
	@bash tools/check.sh smoke
