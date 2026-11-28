# Hemlig k3s testbed

Ansible playbooks that install and remove a single-node [k3s](https://k3s.io) cluster with cert-manager on a long-lived Linux VM. Use it to run the Kubernetes acceptance gates (PKI-5, PKI-6 and PKI-8 in [docs/operations/acceptance.md](../docs/operations/acceptance.md)) against a real cluster.

The cluster is disposable and not for production. It has one node, no backups and no high availability.

## Requirements

- Ansible core 2.15 or later on your machine.
- SSH access, with passwordless or prompted sudo, to a fresh Debian 12/13 or Ubuntu 24.04 VM. It needs at least 2 vCPUs, 4 GiB RAM and amd64 or arm64.
- The VM's host key in your `known_hosts`. Host key checking stays on.

## Set up the inventory

```sh
cp testbed/inventory.example.yml testbed/inventory.yml
```

Edit `testbed/inventory.yml` with your VM's address and user. The file is gitignored; never commit a real inventory. The example lists every variable you can override.

## Bring it up and tear it down

```sh
yarn testbed:up
yarn testbed:down
```

`testbed:up` is idempotent: a second run changes nothing. It prints an `export KUBECONFIG=...` line at the end:

```sh
export KUBECONFIG=$PWD/testbed/.kube/k3s-testbed.yaml
kubectl get nodes
```

The kubeconfig is written to `testbed/.kube/<inventory hostname>.yaml` (gitignored, mode 0600). Its context, cluster and user are named `hemlig-testbed-<inventory hostname>`.

`testbed:down` runs the k3s uninstall script, which removes k3s, its data and its containers. It also removes `/etc/rancher/k3s` and the local kubeconfig, and leaves the VM and its OS intact. The playbook refuses to run without `-e confirm=yes` because it destroys all cluster state. The yarn script passes it, so running `yarn testbed:down` is the explicit confirmation.

## What it installs

| Component | Default version | Variable |
| --- | --- | --- |
| k3s | `v1.36.6+k3s1` | `k3s_version` |
| cert-manager | `v1.20.5` | `cert_manager_version` |

- k3s comes from the official install script at `get.k3s.io`, downloaded to a file and then run. It reinstalls only when the binary is missing or its version differs.
- Server config is `/etc/rancher/k3s/config.yaml`: kubeconfig mode `0600`, `tls-san` set to `testbed_api_address` (default `ansible_host`), and Traefik disabled. ServiceLB and local-path storage stay on.
- cert-manager is applied from the official release manifest with server-side apply (`k3s kubectl apply --server-side`), and only when `kubectl diff` reports drift. This leaves the `caBundle` that cainjector writes into the webhook configurations alone, so reruns stay unchanged. The manifest is verified against `cert_manager_manifest_sha256`. Pinning the checksum is recommended; the default matches the default version, so set a new digest when you change `cert_manager_version`, or set it to an empty string to skip verification.
- `testbed_extra_manifests` is a list of local manifest files applied after cert-manager. The default is empty.
- Pods resolve DNS through the host's upstream nameservers, written to `/etc/rancher/k3s/resolv.conf` without the host's `search` domains (`testbed_pod_resolv_conf`). With `ndots:5`, a host search domain makes musl-based images and the controller fail to resolve external names.

## Install the Hemlig controller from this checkout

```sh
helm upgrade --install hemlig-controller \
  packages/kubernetes-controller/chart/hemlig-controller \
  --namespace hemlig-system --create-namespace
```

Add `--set` flags or a values file as the gate requires. The controller image must be pullable from the VM. See [Kubernetes controller](../docs/guide/kubernetes.md) for the install and bootstrap steps, and [Configuration](../docs/reference/configuration.md) for chart values.
