# CryptoSight On-Prem Probe

  A lightweight Python agent that gives CryptoSight visibility into private-network
  cryptographic assets that no cloud-side vendor API can reach.

  Three discovery modes run simultaneously:

  1. **Active TLS scanner** — dials each host:port in configured CIDR ranges and extracts the full certificate chain.
  2. **Local certificate store reader** — walks PEM/DER files on the host filesystem.
  3. **Passive traffic sniffer** — watches live network traffic via libpcap and extracts TLS handshake metadata (SNI, cipher suites, certificates).

  ---

  ## Install (Docker — recommended)

  **Prerequisites:** [Docker Desktop](https://docs.docker.com/get-docker/) (any OS). No Go, Python, or source code required — the pre-built image is pulled automatically.

  **Step 1 — Download the two config files**

  ```bash
  curl -LO https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/docker-compose.yml
  curl -LO https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/config.yaml.example
  mv config.yaml.example config.yaml
  ```

  Windows (PowerShell):

  ```powershell
  Invoke-WebRequest -Uri https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/docker-compose.yml -OutFile docker-compose.yml
  Invoke-WebRequest -Uri https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/config.yaml.example -OutFile config.yaml
  ```

  **Step 2 — Edit `config.yaml`**

  Open `config.yaml` and fill in three fields:

  ```yaml
  probe:
    name: "office-network"          # a label shown in the CryptoSight UI
    apiKey: "csp_your_key_here"     # from the Probes page → Register Probe
    endpoint: "https://your-tenant.replit.app/api"
  ```

  Also set the CIDR ranges to scan under `scan.networks`.

  **Step 3 — Start the probe**

  ```bash
  docker compose up -d
  docker compose logs -f
  ```

  The probe pulls the pre-built image from GitHub Container Registry (~150 MB, Python 3.12 slim),
  starts scanning, and ships findings to your CryptoSight instance.

  **To stop:**

  ```bash
  docker compose down
  ```

  **To update to the latest version:**

  ```bash
  docker compose pull && docker compose up -d
  ```

  ---

  ## Configuration reference

  ### `probe` section

  | Field | Required | Description |
  |---|---|---|
  | `name` | ✓ | Label shown in the CryptoSight UI (e.g. `datacenter-east`). |
  | `apiKey` | ✓ | Bearer token from the Probes page. Keep secret. |
  | `endpoint` | ✓ | Your CryptoSight base URL, no trailing slash. |

  ### `scan` section

  | Field | Default | Description |
  |---|---|---|
  | `networks` | — | CIDR ranges to scan for TLS endpoints. |
  | `ports` | `[443, 8443, 636, 5671, 8080, 9200, 3269]` | TCP ports to probe. |
  | `concurrency` | `50` | Max simultaneous TLS connections. |
  | `timeoutSeconds` | `5` | Per-host connect + handshake timeout. |
  | `schedule` | (one-shot) | 5-field cron expression, e.g. `"0 2 * * *"`. |

  ### `certStore` section

  | Field | Default | Description |
  |---|---|---|
  | `enabled` | `false` | Walk local PEM/DER cert directories. |
  | `paths` | — | Directories to scan (e.g. `/etc/ssl/certs`). |

  ### `mode` section

  | Field | Default | Description |
  |---|---|---|
  | `activeScan` | `true` | Run the active TLS scanner. |
  | `passiveSniffer` | `false` | Enable passive pcap capture (see below). |

  ---

  ## Passive sniffer (optional)

  The sniffer captures live TLS handshakes off the wire — showing what crypto is
  actually *in use* including short-lived internal connections invisible to cert stores.

  **Requires:** Linux host, Docker with `NET_RAW`/`NET_ADMIN` capabilities, `network_mode: host`.
  Not available on Docker Desktop for Mac or Windows (VM networking prevents host packet capture).

  **Enable:**

  1. In `config.yaml`, set `mode.passiveSniffer: true` and `sniffer.interface: eth0` (or your interface name — run `ip link` to list them).

  2. In `docker-compose.yml`, uncomment the three blocks:
     ```yaml
     cap_add:
       - NET_ADMIN
       - NET_RAW
     security_opt:
       - apparmor:unconfined
     network_mode: host
     ```

  3. Restart: `docker compose up -d`

  ---

  ## Kubernetes (DaemonSet)

  A DaemonSet runs one probe per node. With `hostNetwork: true`, each pod shares
  the node's network namespace for cluster-wide TLS visibility.

  **kubectl + kustomize:**

  ```bash
  # 1. Clone the repo
  git clone https://github.com/WaltPdub/cryptosight-probe.git
  cd cryptosight-probe

  # 2. Set your endpoint and API key
  vim k8s/configmap.yaml

  # 3. Apply
  kubectl apply -k k8s/

  # 4. Watch
  kubectl get pods -n cryptosight -w
  kubectl logs -n cryptosight daemonset/cryptosight-probe -f
  ```

  **Helm:**

  ```bash
  kubectl create namespace cryptosight

  helm install cryptosight-probe helm \
    --namespace cryptosight \
    --set-string probe.apiKey="csp_YOUR_KEY_HERE" \
    --set probe.endpoint="https://your-tenant.replit.app/api"
  ```

  Key Helm values:

  | Key | Default | Description |
  |---|---|---|
  | `probe.apiKey` | — | Plaintext API key (use `probe.existingSecret` for production). |
  | `probe.endpoint` | — | Your CryptoSight URL. |
  | `probe.namePrefix` | `k8s` | Per-node probe name prefix (`<prefix>-<nodeName>`). |
  | `sniffer.interface` | `any` | Interface to capture. |
  | `resources.limits.memory` | `512Mi` | Increase on busy nodes. |

  ---

  ## Troubleshooting

  | Symptom | Fix |
  |---|---|
  | `401 Unauthorized` | Wrong `apiKey` — regenerate on the Probes page. |
  | `404 Not Found` | Wrong `endpoint` URL or probe was deleted. |
  | All hosts time out | Increase `scan.timeoutSeconds` or reduce `scan.concurrency`. |
  | `parsing config: …` | YAML indentation error — validate the file. |
  | Sniffer: `Operation not permitted` | Missing `cap_add: NET_RAW/NET_ADMIN` in docker-compose.yml. |
  | Sniffer: `No such device` | Wrong interface name — run `ip link` on the host. |
  | Sniffer captures nothing | `network_mode: host` not set — bridge mode only sees container traffic. |
  | Sniffer not available | Docker Desktop (Mac/Windows) does not support host networking. |

  ---

  ## How assets reach the inventory

  ```
  probe → POST /api/probes/ingest (Bearer csp_...)
           ↓
           server: validate → deduplicate → upsert
           source = "probe:<name>"
  ```

  The same certificate found by the probe and a cloud sensor (e.g. Vault) deduplicates
  to one inventory row — the probe observation adds a location, not a duplicate.

  ---

  ## Security notes

  - The probe process runs as a **non-root** user inside the container.
  - The API key is read from the config file at startup — never passed as an env var or CLI argument.
  - The active scanner uses `check_hostname=False` intentionally: an expired or untrusted cert is still a crypto asset that belongs in the inventory.
  - Never commit `config.yaml` to source control; it contains your API key.
  