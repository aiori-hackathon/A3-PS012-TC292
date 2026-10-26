.PHONY: test lab-up lab-down lab-status lab-logs lab-run lab-ping demo scan compare report verify-rate

PYTHON ?= python3
SRC := src
LAB := $(SRC)/lab

# Run unit tests (no Docker required). This is the Phase 2 verification target.
test:
	cd $(SRC) && $(PYTHON) -m pytest

# Start the Docker lab (20 targets + test-zone server + client container).
lab-up:
	cd $(LAB) && docker compose up -d --build
	@echo "Lab starting. Run 'make lab-status' to check health."

lab-status:
	cd $(LAB) && docker compose ps

lab-down:
	cd $(LAB) && docker compose down

lab-logs:
	cd $(LAB) && docker compose logs -f --tail=50

# Run a command inside the lab client container (has network reach to all targets).
# Usage: make lab-run CMD="-m dnsassess.cli scan --scope config/scope.yaml --rate config/rate.yaml"
lab-run:
	cd $(LAB) && docker exec -t lab-client python3 $(CMD)

# Client connectivity check: run DNS probe from inside the client container.
lab-ping:
	cd $(LAB) && docker exec -t lab-client python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x04test\\x00\\x00\\x01\\x00\\x01', ('172.28.0.101',53)); s.recvfrom(512); s.close(); print('t01: OK')" 2>&1 || echo "t01: UNREACHABLE"

# Full demo (wired up in later phases once cli.py exists).
demo: lab-up scan compare report

scan:
	cd $(SRC) && $(PYTHON) -m dnsassess.cli scan --scope config/scope.yaml --rate config/rate.yaml

compare:
	cd $(SRC) && $(PYTHON) -m dnsassess.cli compare

report:
	cd $(SRC) && $(PYTHON) -m dnsassess.cli report

verify-rate:
	@echo "Packet-capture rate verification requires the Docker lab; see build prompt section 9."
