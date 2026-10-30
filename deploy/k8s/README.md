# deploy/k8s

Kustomize manifests for the page-capture stack on Kubernetes (S3 mode).

- `capture/`: the **base**, production shape (capture-browser, capture-proxy, NetworkPolicy). No store, no secret values.
- `lab/`: a **test-only overlay** adding an in-cluster RustFS store. Used by `scripts/kind-lab.sh`.

`kubectl apply -k deploy/k8s/capture` (base) or `deploy/k8s/lab` (lab; needs the Secrets that `scripts/kind-lab.sh up` creates).

See [docs/deploy/kubernetes.md](../../docs/deploy/kubernetes.md).
