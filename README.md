# CryptoSight On-Prem Probe

A lightweight Go binary that gives CryptoSight visibility into private-network
cryptographic assets that no cloud-side vendor API can reach.

The probe supports three discovery modes that can run simultaneously:

1. **Active TLS scanner** — dials each host:port in configured CIDR ranges and
   extracts the full certificate chain from the TLS handshake.
2. **Local certificate store reader** — walks PEM/DER files on the host
   filesystem.
3. **Passive traffic sniffer** — watches live network traffic via libpcap and
   extracts TLS handshake metadata: SNI hostnames, negotiated cipher suites, and
   certificates from ServerHello Certificate messages.  Shows what cryptographic
   algorithms are actually *in use on the wire* — including short-lived internal
   connections and legacy cipher negotiations that would never appear in a cert
   store.

All findings are shipped to the CryptoSight ingest API so they appear in the
central inventory alongside cloud-discovered assets.

---

## Prerequisites

| Tool | Minimum version | Required for |
|---|---|---|
| Docker | 20.10 | Building and running the image |
| docker compose | v2 | `docker compose up` |
| Go | 1.22 + libpcap-dev | Local builds only |

The Docker image is built on `alpine:3.19` with only `libpcap` and
`ca-certificates` installed (no shell, no package manager available to an
attacker).  The passive sniffer requires CGO + libpcap, which is why the image
changed from `distroless/static` (no libc, incompatible) to Alpine (musl-based,
fully compatible).

---

## Get the probe

```bash
git clone https://github.com/WaltPdub/cryptosight-probe.git
cd cryptosight-probe
```

---

## Quick start (Docker)

```bash
# 1. Copy and edit the example config
cp config.yaml.example config.yaml
$EDITOR config.yaml          # fill in probe.name, probe.apiKey, probe.endpoint

# 2. Build the image
docker compose build

# 3. Run once (one-shot — omit scan.schedule in config)
docker compose run --rm cryptosight-probe

# 4. Or run continuously on a schedule
docker compose up -d
docker compose logs -f
```

### docker run (without Compose)

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/config/config.yaml:ro" \
  cryptosight/probe:latest
```

---

## Local build (without Docker)

```bash
# Requires Go 1.22+ and libpcap-dev (for the passive sniffer)
# Debian/Ubuntu:  sudo apt-get install libpcap-dev
# Alpine:         apk add libpcap-dev gcc musl-dev
# macOS:          brew install libpcap  (pcap is pre-installed on most macOS)

git clone https://github.com/WaltPdub/cryptosight-probe.git
cd cryptosight-probe
go mod tidy                  # generates go.sum, downloads gopacket
CGO_ENABLED=1 go build -o cryptosight-probe .
./cryptosight-probe --config config.yaml
```

To produce a dynamically-linked Linux/amd64 binary (required for libpcap):

```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
  -o cryptosight-probe .
```

> **Active scan only (no sniffer):** The passive sniffer is enabled at runtime
> via `mode.passiveSniffer: true` in the config.  If you never enable it, you
> can still build with `CGO_ENABLED=1` and the pcap dependency is loaded lazily —
> or keep `CGO_ENABLED=0` and only the `activeScan` + `certStore` modes will be
> available (the sniffer will fail to open a pcap handle at runtime).

---

## Configuration reference

The probe reads a single YAML file (default path: `/config/config.yaml` inside
Docker, `./config.yaml` locally).  Pass a custom path with `--config`.

### `probe` section

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | ✓ | Logical name shown in the CryptoSight UI (e.g. `datacenter-east`). Assets are sourced as `probe:<name>`. |
| `apiKey` | string | ✓ | Bearer token generated on the **Probes** page. Treat like a password. |
| `endpoint` | string | ✓ | Base URL of your CryptoSight instance, e.g. `https://acme.replit.app/api`. No trailing slash. |

### `scan` section

| Field | Type | Default | Description |
|---|---|---|---|
| `networks` | list of CIDRs | — | IP ranges to scan for TLS endpoints. |
| `ports` | list of integers | `[443, 8443, 636, 5671, 8080, 9200, 3269]` | TCP ports to probe on each host. |
| `concurrency` | integer | `50` | Maximum simultaneous TLS dial goroutines. |
| `timeoutSeconds` | integer | `5` | TCP connect + TLS handshake timeout per target. |
| `schedule` | string | (empty) | Standard 5-field cron expression. Omit for a one-shot run. |

> **Large CIDR ranges** — scanning a /8 (16 M hosts) at concurrency=50 with a
> 5 s timeout takes approximately 23 hours.  Use /24 or /16 ranges for routine
> scans and reserve /8 for deep discovery runs on a long schedule.

### `certStore` section

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable local certificate store reading. |
| `paths` | list of strings | — | Directories to walk for `.pem`, `.crt`, `.cer`, `.der` files. |

Common Linux paths:

| Distribution | Path |
|---|---|
| Debian / Ubuntu | `/etc/ssl/certs` |
| RHEL / CentOS / Fedora | `/etc/pki/tls/certs` |
| Alpine | `/etc/ssl/certs` |

### `mode` section

| Field | Type | Default | Description |
|---|---|---|---|
| `activeScan` | boolean | `true` | Run the active TLS scanner. |
| `passiveSniffer` | boolean | `false` | Enable passive pcap-based TLS traffic capture. Requires `NET_ADMIN` + `NET_RAW` capabilities and `network_mode: host` (see below). |

Both modes may be set to `true` simultaneously — they run in separate goroutines
and send independently to the ingest API.  Assets from both sources deduplicate
server-side by fingerprint.

### `sniffer` section

Only read when `mode.passiveSniffer: true`.

| Field | Type | Default | Description |
|---|---|---|---|
| `interface` | string | — | Network interface to capture on (e.g. `eth0`, `any`). **Required when passiveSniffer is true.** |
| `bpfFilter` | string | `"tcp port 443 or tcp port 8443"` | libpcap BPF filter applied before TLS parsing. |
| `flushIntervalSeconds` | integer | `60` | How often to ship buffered assets to the API. |
| `maxBufferAssets` | integer | `500` | Trigger an early flush when the buffer holds this many unique assets. |

---

## Passive sniffer

### What it captures

The sniffer opens the network interface in promiscuous mode and uses
`google/gopacket` with TCP stream reassembly to parse TLS handshake messages:

| TLS Message | Extracted data |
|---|---|
| **ClientHello** | SNI hostname (used to annotate cert assets with the server name) |
| **ServerHello** | Chosen cipher suite → emitted as a `type="crypto_library"` asset with the quantum-vulnerability flag |
| **Certificate** | Raw DER certificate chain → same `x509.Certificate` → `DiscoveredAsset` pipeline as the active scanner |

Captured assets have `source="network_capture"` and `sourceType="network"`.
Cipher-suite-only observations (no cert captured) carry
`customMetadata.cipherSuite = <hex id>`.

### Required Linux capabilities

Add all three of the following to `docker-compose.yml` when
`mode.passiveSniffer: true`:

```yaml
cap_add:
  - NET_ADMIN    # set the NIC to promiscuous mode
  - NET_RAW      # open a raw packet socket

security_opt:
  - apparmor:unconfined   # some distros block raw sockets via AppArmor

network_mode: host        # share the host network namespace so the probe
                          # sees traffic on the physical interface
                          # (bridge mode only exposes container-own traffic)
```

> **Security note:** `NET_RAW` + `NET_ADMIN` + `network_mode: host` materially
> expand the container's attack surface.  Add them only when the sniffer is in
> active use and remove them for active-scan-only deployments.

### Enabling sniffer mode — step by step

```bash
# 1. Edit config.yaml
vim config.yaml
#    mode:
#      passiveSniffer: true
#    sniffer:
#      interface: "eth0"   # or the actual interface name

# 2. Uncomment the three blocks in docker-compose.yml (cap_add, security_opt, network_mode)
vim docker-compose.yml

# 3. Rebuild (adds libpcap, CGO_ENABLED=1 — takes ~60 s first time)
docker compose build

# 4. Run (needs host networking — cannot use docker compose run easily)
docker compose up -d

# 5. Verify the sniffer is capturing
docker compose logs -f
# Expected: INFO: passive sniffer started on interface "eth0" (flush every 1m0s, max buffer 500)
# After first flush: INFO: sniffer ingest complete — accepted=N rejected=0
```

### Verifying capture is working

Generate some TLS traffic on the monitored interface, then check the logs:

```bash
# From another shell on the same host:
curl -s https://example.com > /dev/null

# In the probe logs you should eventually see:
# INFO: sniffer flushing N asset(s) to https://...
# INFO: sniffer ingest complete — accepted=N rejected=0
```

### Cloud / Kubernetes environments

Docker's `network_mode: host` is a Linux-only feature and is unavailable in
Docker Desktop on macOS/Windows.  In Kubernetes, deploy the probe as a
**DaemonSet** with `hostNetwork: true` so each pod shares its node's network
namespace and can sniff traffic on the physical interface.

See the full deployment guide in the next section: [Kubernetes deployment](#kubernetes-deployment-daemonset).

### Out of scope

- **TLS decryption** — impossible without the server's private key.  The sniffer
  extracts handshake metadata and the certificate chain only.
- **TLS 1.3 0-RTT** — the Certificate message is encrypted in 0-RTT; only
  resumed sessions are visible.
- **Windows / macOS packet capture** — the Docker image is Linux-only.  macOS
  local builds work with Homebrew's `libpcap` but the container sniffer requires
  Linux host networking.

---

## How assets reach the inventory

```
probe → POST /api/probes/ingest  (Bearer csp_...)
         ↓
         server validate → dedupe → upsert
         source = "probe:<name>"
```

Each certificate is identified by its SHA-256 fingerprint.  If the same cert
is later discovered by a cloud-side sensor (e.g. Vault or MDE) it deduplicates
to the same inventory row — the probe observation adds a second *location*
rather than a second asset.

---

## Troubleshooting

### Active scan / general

| Symptom | Fix |
|---|---|
| `401 Unauthorized` | Check `probe.apiKey` — generate a new key on the Probes page if needed. |
| `404 Not Found` | Verify `probe.endpoint` and that the probe is still registered (not revoked). |
| `connection refused` on all hosts | The probe container may not have network access to the target range — check `docker network` settings or host firewall rules. |
| All hosts time out | Increase `scan.timeoutSeconds` or reduce `scan.concurrency` to avoid overwhelming a slow network. |
| `parsing config "…": …` | Validate YAML syntax — indentation errors are the most common cause. |

### Passive sniffer

| Symptom | Fix |
|---|---|
| `opening pcap on "eth0": Operation not permitted` | The container lacks `NET_RAW`/`NET_ADMIN` caps.  Uncomment the `cap_add` block in `docker-compose.yml`. |
| `opening pcap on "eth0": No such device` | Wrong interface name.  Run `ip link` on the host to list interfaces. Use `"any"` to capture on all. |
| Sniffer starts but captures no assets after traffic | Verify `network_mode: host` is uncommented.  In bridge mode the probe only sees its own traffic. |
| Container exits with `pcap packet source closed unexpectedly` | The interface went away (e.g. container restart, bonding change).  Restart the probe. |
| Sniffer only captures self-traffic in Docker Desktop (macOS/Windows) | Docker Desktop's VM doesn't support `network_mode: host`.  The passive sniffer requires a Linux host. |
| High memory usage on busy interfaces | Reduce `sniffer.maxBufferAssets` and `sniffer.flushIntervalSeconds`, and increase the container memory limit in `docker-compose.yml`. |
| `sniffer.interface is required` error | Add `sniffer: interface: "eth0"` to `config.yaml`. |

### Kubernetes (DaemonSet)

| Symptom | Fix |
|---|---|
| `Operation not permitted` on pcap open | Pod is missing `NET_RAW`/`NET_ADMIN` capabilities — check `securityContext.capabilities.add` in the DaemonSet spec. |
| Sniffer starts but sees no traffic | Verify `hostNetwork: true` and `dnsPolicy: ClusterFirstWithHostNet` are set.  Without host networking, the pod only sees CNI overlay traffic. |
| `No such device` on interface `"any"` | Some kernels require a real interface name.  Run `kubectl exec <pod> -- ip link` to list available interfaces. |
| Pod crash-loops with `permission denied` | Some distributions (e.g. GKE COS) block raw sockets even with capabilities.  Try setting `seccompProfile.type: Unconfined` as a test; if that fixes it, add a custom seccomp profile or AppArmor annotation. |
| initContainer fails: `sed: can't open ...` | The ConfigMap name or key does not match.  Check `kubectl describe configmap -n cryptosight`. |
| Config-init hangs | `NODE_NAME` env var is missing — confirm `fieldRef: spec.nodeName` is present. |
| High memory on busy nodes | Increase `resources.limits.memory` in the DaemonSet.  Reduce `sniffer.maxBufferAssets` to cap the reassembler's per-flow buffer. |
| Pods not scheduled on control-plane | Add the `node-role.kubernetes.io/control-plane` toleration or use `tolerations: [{operator: Exists}]`. |

---

## Kubernetes deployment (DaemonSet)

A DaemonSet runs exactly one probe per cluster node.  Combined with
`hostNetwork: true`, each pod shares the node's network namespace and captures
TLS handshakes on all physical interfaces — the only topology that gives
cluster-wide cryptographic visibility.

### Architecture

```
┌─ Node A ────────────────┐   ┌─ Node B ────────────────┐
│  [cryptosight-probe pod]│   │  [cryptosight-probe pod]│
│  hostNetwork: true      │   │  hostNetwork: true      │
│  NET_ADMIN + NET_RAW    │   │  NET_ADMIN + NET_RAW    │
│  pcap → eth0            │   │  pcap → eth0            │
└────────┬────────────────┘   └────────┬────────────────┘
         │  POST /api/probes/ingest         │
         └──────────────┬──────────────────┘
                        ▼
              CryptoSight API (cloud)
              deduplicate → inventory
```

Each node's probe is identified as `k8s-<nodeName>` in the inventory so you
can see exactly which nodes contributed which findings.

---

### Quick start — kubectl + kustomize

```bash
# 1. Clone the repo
git clone https://github.com/WaltPdub/cryptosight-probe.git
cd cryptosight-probe

# 2. Edit the ConfigMap to set your endpoint
#    IMPORTANT: replace "REPLACE_WITH_YOUR_API_KEY" with an actual key
#    generated on the Probes page.  For production, use a Secret instead
#    (see "Securing the API key" below).
vim k8s/configmap.yaml

# 3. Apply all resources (creates namespace, ConfigMap, ServiceAccount, DaemonSet)
kubectl apply -k k8s/

# 4. Watch pods come up — one per node
kubectl get pods -n cryptosight -w

# 5. Check sniffer is capturing on a specific node
kubectl logs -n cryptosight daemonset/cryptosight-probe -f
# Expected: INFO: passive sniffer started on interface "any" ...
# After first flush: INFO: sniffer ingest complete — accepted=N rejected=0
```

---

### Quick start — Helm

```bash
# 0. Clone the repo (skip if already cloned for kustomize)
git clone https://github.com/WaltPdub/cryptosight-probe.git
cd cryptosight-probe

# 1. Create the namespace first (chart does not create it by default)
kubectl create namespace cryptosight

# 2. Install with your API key and endpoint
helm install cryptosight-probe helm \
  --namespace cryptosight \
  --set-string probe.apiKey="csp_YOUR_KEY_HERE" \
  --set probe.endpoint="https://your-instance.replit.app/api"

# Alternatively, let the chart own the namespace (Helm-tracked resource):
# helm install cryptosight-probe probes/cryptosight-probe/helm \
#   --namespace cryptosight \
#   --set createNamespace=true \
#   --set-string probe.apiKey="csp_..." \
#   --set probe.endpoint="https://..."
# Do NOT combine --create-namespace with createNamespace=true — both try to
# create the same namespace object and Helm will error on the conflict.

# 2. Watch the rollout
kubectl rollout status daemonset/cryptosight-probe-cryptosight-probe -n cryptosight

# 3. Stream logs from all nodes
kubectl logs -n cryptosight -l app.kubernetes.io/name=cryptosight-probe -f

# Upgrade (e.g. to change the BPF filter)
helm upgrade cryptosight-probe probes/cryptosight-probe/helm \
  --reuse-values \
  --set sniffer.bpfFilter="tcp port 443"

# Uninstall
helm uninstall cryptosight-probe -n cryptosight
```

Key `values.yaml` options:

| Key | Default | Description |
|---|---|---|
| `probe.namePrefix` | `k8s` | Prefix for per-node probe names (`<prefix>-<NODE_NAME>`). |
| `probe.apiKey` | — | Plaintext API key (prefer `probe.existingSecret`). |
| `probe.endpoint` | — | Your CryptoSight instance URL (no trailing slash). |
| `probe.existingSecret.name` | — | Pre-existing Secret name holding the key. |
| `sniffer.interface` | `any` | Interface to capture (use `any` for all). |
| `sniffer.bpfFilter` | (TLS ports) | libpcap BPF expression. |
| `sniffer.flushIntervalSeconds` | `60` | How often stats + assets are shipped. |
| `resources.limits.memory` | `512Mi` | Increase on high-traffic nodes. |
| `tolerations` | all effects | Control which nodes receive the probe. |
| `certStore.enabled` | `false` | Also scan the node's OS trust store. |

---

### Securing the API key

**Do not store the plaintext API key in the ConfigMap.**  The ConfigMap is
readable by any pod in the same namespace.  Instead:

```bash
# Create a Secret (kubectl)
kubectl create secret generic cryptosight-probe-secret \
  --namespace cryptosight \
  --from-literal=apiKey="csp_YOUR_KEY_HERE"
```

Then in `k8s/configmap.yaml`, change the template placeholder:

```yaml
apiKey: "${API_KEY}"   # ← was hardcoded, now a template variable
```

And in `k8s/daemonset.yaml`, add to the `config-init` initContainer's `env`:

```yaml
- name: API_KEY
  valueFrom:
    secretKeyRef:
      name: cryptosight-probe-secret
      key: apiKey
```

With Helm, use `probe.existingSecret`:

```bash
kubectl create secret generic my-probe-secret \
  -n cryptosight --from-literal=apiKey="csp_..."

helm install cryptosight-probe probes/cryptosight-probe/helm \
  --set probe.existingSecret.name=my-probe-secret \
  --set probe.endpoint="https://your-instance.replit.app/api"
```

---

### Required capabilities and RBAC

The probe pod needs two Linux capabilities:

| Capability | Why |
|---|---|
| `NET_RAW` | Open a raw packet socket for libpcap. |
| `NET_ADMIN` | Set the NIC to promiscuous mode. |

These are added via `securityContext.capabilities.add` — **no `privileged: true`
is needed**.  The pod does *not* require any Kubernetes RBAC permissions
(no ClusterRole or RoleBinding is created — the ServiceAccount is present only
as a hook for cloud IAM annotations such as EKS IRSA).

---

### Per-node probe names

Each pod's config is rendered by an `initContainer` that substitutes
`${NODE_NAME}` with the actual Kubernetes node name before the main probe
starts.  This means every node registers as a distinct probe in the inventory
(e.g. `k8s-ip-10-0-1-42`, `k8s-ip-10-0-1-43`), making it easy to correlate
findings with specific hosts.

To change the naming scheme, edit `probe.namePrefix` in `values.yaml` (Helm)
or the `name:` line in `k8s/configmap.yaml` (kustomize).

---

### Scanning the node's OS certificate store

To also read certificates from each node's `/etc/ssl`, enable `certStore` and
uncomment the `host-certs` hostPath volume in `daemonset.yaml`:

```yaml
# In daemonset.yaml — volumes section
- name: host-certs
  hostPath:
    path: /etc/ssl
    type: Directory

# In daemonset.yaml — container volumeMounts
- name: host-certs
  mountPath: /host-certs/ssl
  readOnly: true
```

With Helm: `--set certStore.enabled=true`.

---

### Applying ConfigMap changes

The initContainer renders config once at pod startup.  After editing the
ConfigMap, trigger a rolling restart:

```bash
# kubectl
kubectl rollout restart daemonset/cryptosight-probe -n cryptosight

# Helm (no values change needed — Helm detects ConfigMap hash change)
helm upgrade cryptosight-probe probes/cryptosight-probe/helm --reuse-values
```

---

## Security notes

- The probe binary runs as a **non-root** user inside the distroless image.
- The API key is read from the config file at startup; it is not exposed in
  environment variables or command-line arguments.
- `InsecureSkipVerify` is set on the TLS dialer used for *cert extraction*.
  This is intentional — an untrusted or expired cert is still an asset that
  must appear in the inventory.  The probe's own outbound HTTPS connection to
  the CryptoSight API uses normal trust verification.
- Never commit `config.yaml` to source control; the API key is a secret.
