.PHONY: test lab-up lab-down lab-status lab-logs lab-run lab-ping demo scan compare report verify-rate verify-stability

UV ?= uv
SRC := src
LAB := $(SRC)/lab

# Run unit tests (no Docker required). Uses uv.
test:
	cd $(SRC) && $(UV) run pytest

# Start the Docker lab (20 targets + test-zone server + separate client).
lab-up:
	cd $(LAB) && docker compose up -d --build --remove-orphans
	@echo "Lab starting. Run 'make lab-status' to check health."

lab-status:
	cd $(LAB) && docker compose ps

lab-down:
	cd $(LAB) && docker compose down

lab-logs:
	cd $(LAB) && docker compose logs -f --tail=50

# Run a command inside the separate lab client container.
# Usage: make lab-run CMD="-m dnsassess.cli scan --scope config/scope.yaml --rate config/rate.yaml"
lab-run:
	cd $(LAB) && docker exec -t lab-client python3 $(CMD)

# Client connectivity check: run DNS probe from inside the client container.
lab-ping:
	cd $(LAB) && docker exec -t lab-client python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x04test\\x00\\x00\\x01\\x00\\x01', ('172.28.0.101',53)); s.recvfrom(512); s.close(); print('t01: OK')" 2>&1 || echo "t01: UNREACHABLE"

# One-command lab-up, scan, compare, and report workflow.
demo:
	$(UV) run --directory $(SRC) python run_demo.py

scan:
	cd $(SRC) && $(UV) run -m dnsassess.cli scan --scope config/scope.yaml --rate config/rate.yaml

compare:
	cd $(SRC) && $(UV) run -m dnsassess.cli compare

report:
	cd $(SRC) && $(UV) run -m dnsassess.cli report

verify-rate:
	cd $(SRC) && $(UV) run python verify_rate.py

verify-stability:
	cd $(LAB) && docker exec lab-client python3 -m dnsassess.cli verify-stability --scope /app/config/scope.yaml --rate /app/config/rate.yaml --out /app/out/stability --seed phase4-stability --auth-log /var/log/authzone/queries.jsonl
