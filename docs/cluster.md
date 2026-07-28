# Cluster mode

Cluster mode is intended for two or more PamOlive application VMs sharing the same
database, Redis, keyring service, and recording storage.

## Recommended two-VM shape

```text
pamolive.mopacy.be
  -> load balancer / reverse proxy
    -> VM 1: web, worker, gateway, rdp-broker, beat
    -> VM 2: web, worker, gateway, rdp-broker

Shared services:
  PostgreSQL, Redis TLS, keyring, recordings storage
```

Only one `beat` process should run until a distributed scheduler lock is added.

## Edition rules

- Community: cluster disabled.
- Lab: cluster enabled for evaluation, max 5 active users and 2 targets.
- Business/Enterprise: cluster enabled only with a valid signed license.

## Single-machine evaluation

Use `compose.cluster-lab.yml` to simulate two application nodes on one Docker host.
This does not make the installation highly available; it only validates routing,
shared state, and node identification.

```bash
PAMOLIVE_EDITION=lab PAMOLIVE_CLUSTER_ENABLED=true \
docker compose -f compose.yml -f compose.cluster-lab.yml up -d --build
```

Then call `/api/health/` repeatedly and verify the reported `node_id`.

