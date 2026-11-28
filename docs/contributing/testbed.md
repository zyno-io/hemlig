---
title: k3s testbed
description: Bring up and tear down a disposable single-node k3s cluster with Ansible to run the Kubernetes acceptance gates.
pageType: how-to
---

# k3s testbed

Install or remove a single-node k3s cluster with cert-manager on a Linux VM, so you can run the Kubernetes acceptance gates against a real cluster.

**Before you start**

- Ansible core 2.15 or later.
- SSH access with sudo to a fresh Debian 12/13 or Ubuntu 24.04 VM with at least 2 vCPUs and 4 GiB RAM.
- The VM's host key in your `known_hosts`.
- About ten minutes.

The cluster is disposable and not for production. The playbooks live in [`testbed/`](https://github.com/zyno-io/hemlig/tree/main/testbed), and the [README](https://github.com/zyno-io/hemlig/blob/main/testbed/README.md) lists every variable.

## Create the inventory

The real inventory is gitignored. Copy the example and set the address and user of your VM.

```sh
cp testbed/inventory.example.yml testbed/inventory.yml
```

## Bring the cluster up

The playbook installs a pinned k3s with Traefik disabled, then a pinned cert-manager. It is idempotent.

```sh
yarn testbed:up
```

Expected output ends with the line to export:

```text
export KUBECONFIG=/path/to/hemlig/testbed/.kube/k3s-testbed.yaml
```

## Install the controller

Install the chart from your checkout, then continue with [Kubernetes controller](../guide/kubernetes.md).

```sh
export KUBECONFIG=$PWD/testbed/.kube/k3s-testbed.yaml
helm upgrade --install hemlig-controller \
  packages/kubernetes-controller/chart/hemlig-controller \
  --namespace hemlig-system --create-namespace
```

## Tear the cluster down

The playbook removes k3s, its data and its containers, and leaves the VM intact. It refuses to run without `confirm=yes`, and the yarn script passes it.

```sh
yarn testbed:down
```

## Verify

```sh
kubectl get nodes
kubectl -n cert-manager get deployments
```

Expected output shows the node `Ready` and all three cert-manager deployments `1/1`.

## Next steps

- [AWS acceptance runbook](../operations/acceptance.md) for the gates the testbed serves.
- [Kubernetes controller](../guide/kubernetes.md) for installing and bootstrapping.
