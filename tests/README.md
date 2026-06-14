# Integration test stack

A Docker Compose setup that boots a small Slurm cluster (one controller, one
login node, two compute nodes) plus a single-node etcd, with pcocc installed
in editable mode against the repository checkout.

## Layout

- `compose.yml` (repo root) defines the services.
- `tests/docker/Dockerfile` builds the four images from a common base (Fedora
  43 + Slurm 24.11.5 built from source, matching `example-project/`).
- `tests/docker/pcocc/` is mounted at `/etc/pcocc/` and overrides the stock
  config to point at the `etcd` service and disable etcd auth.
- The repo is mounted read-only at `/pcocc` in every pcocc container, so
  Python edits on the host are picked up without rebuilding (pcocc is
  installed with `pip install -e`).

## Requirements

- Docker + Compose.
- Host kernel with `/dev/kvm` and `/dev/net/tun` accessible to the test user
  (compute nodes pass these in as devices). CI runners without nested-virt
  will fail to start guests but Python-side tests still run.
- The `openvswitch` kernel module loaded on the host (`modprobe openvswitch`).

## Usage

```sh
# Build and start the cluster
docker compose up --force-recreate --build -d --wait

# Run the bats suite (read from the bind-mounted source, not the image copy,
# so edits to tests/*.bats land without a rebuild)
docker compose exec --user user --workdir /home/user login bats /pcocc/tests/pcocc.bats

# Iterate: edit Python source or bats tests, rerun (no rebuild needed)
docker compose exec --user user --workdir /home/user login bats /pcocc/tests/pcocc.bats

# Tear down
docker compose down -v
```
