# Decision 010 — Lab client container for host-to-container DNS access

## Decision
Add a `client` service to `docker-compose.yml` (based on `python:3.11-slim` with
`dnspython` and `PyYAML`) that runs on `lab_net` with static IP `172.28.0.2`.
The prober runs from inside this container via `docker exec lab-client python3
...`. The repo's `src/` tree is mounted at `/app` so the `dnsassess` package
and config files are importable.

## Alternatives considered
- **Run prober from the host** — the host has no route to `172.28.0.0/24`
  (only `eth0` on `172.27.x` and `lo`). DNS queries to container IPs are
  intercepted by a host listener on `10.255.255.254:53` and return NXDOMAIN
  instead of the real server response. Not viable.
- **Publish all 21 container ports to the host** — would require 42 port
  mappings (UDP+TCP per target) and complex `--publish` flags. Fragile and
  hard to maintain.
- **Run prober inside an existing target container** — targets run single
  purpose servers; adding the prober to one would conflate roles and complicate
  the scope (probing yourself).
- **Dedicated client container (chosen)** — clean separation, runs on the same
  Docker network as all targets, can reach every target at its static IP, and
  can read the auth-zone log volume.

## Why
The build prompt specifies a client container ("The client container reaches
targets through published static IPs in 172.28.0.0/24"), but the Phase 1
compose file did not include one. Without it, `make lab-up` starts the lab but
there's no place to run the prober from.

## Trade-offs
- Requires Docker to run the full scan; unit tests still run without Docker.
- `make lab-run CMD="..."` is the escape hatch for running arbitrary commands
  inside the client.
