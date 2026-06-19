# CryptoSight On-Prem Probe

  A lightweight Python agent that gives CryptoSight visibility into private-network
  cryptographic assets that no cloud-side vendor API can reach.

  Three discovery modes run simultaneously:

  1. **Active TLS scanner** — dials each host:port in configured CIDR ranges and extracts the full certificate chain.
  2. **Local certificate store reader** — walks PEM/DER files on the host filesystem.
  3. **Passive traffic sniffer** — watches live network traffic and extracts TLS handshake metadata (SNI, cipher suites, certificates).

  ---

  ## Quick Start (Docker — recommended)

  **Requirements:** [Docker Desktop](https://docs.docker.com/get-docker/) installed and running.
  No Go, Python, or source code needed — the pre-built image is pulled automatically.

  ---

  ### Step 1 — Create a folder and move into it

  **Linux / macOS (Terminal):**
  ```bash
  mkdir cryptosight-probe
  cd cryptosight-probe
  ```

  **Windows (Command Prompt):**
  ```cmd
  mkdir cryptosight-probe
  cd cryptosight-probe
  ```

  ---

  ### Step 2 — Download the two config files

  **Linux / macOS:**
  ```bash
  curl -L -o docker-compose.yml https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/docker-compose.yml
  curl -L -o config.yaml https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/config.yaml.example
  ```

  **Windows (Command Prompt — curl is built in on Windows 10/11):**
  ```cmd
  curl -L -o docker-compose.yml https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/docker-compose.yml
  curl -L -o config.yaml https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/config.yaml.example
  ```

  **Windows (PowerShell):**
  ```powershell
  Invoke-WebRequest -Uri https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/docker-compose.yml -OutFile docker-compose.yml
  Invoke-WebRequest -Uri https://raw.githubusercontent.com/WaltPdub/cryptosight-probe/main/config.yaml.example -OutFile config.yaml
  ```

  ---

  ### Step 3 — Edit config.yaml

  Open `config.yaml` in any text editor (Notepad, VS Code, nano, vim, etc.).

  Find the `probe:` section near the top and fill in the three required fields:

  ```yaml
  probe:
    name: "my-office"                             # Change to any label you like (shown in the UI)
    apiKey: "csp_paste_your_key_here"             # Paste the key from the Probes page
    endpoint: "https://your-tenant.replit.app/api" # Your CryptoSight URL (no trailing slash)
  ```

  **Required for discovery** — find the `scan:` section and add your network CIDR ranges.
  Without at least one range the probe will send heartbeats and stay Online but will not
  discover any assets:

  ```yaml
  scan:
    networks:
      - "192.168.1.0/24"   # add your CIDR ranges, one per line
      - "10.0.0.0/8"
    ports: [443, 8443, 636, 5671, 8080, 9200, 3269]  # TLS ports to probe
    concurrency: 50        # simultaneous connections
    timeoutSeconds: 5      # per-host timeout
    schedule: "0 2 * * *"  # cron for automatic rescans (omit for one-shot)
  ```

  Save the file when done.

  ---

  ### Step 4 — Start the probe

  ```bash
  docker compose up -d
  ```

  Docker pulls the pre-built image from GitHub Container Registry the first time (~150 MB).
  There is no build step.

  ---

  ### Step 5 — Verify it is running

  ```bash
  docker compose logs -f
  ```

  You should see lines like:

  ```
  INFO: CryptoSight probe 'my-office' starting
  INFO: heartbeat sent — probe is Online in CryptoSight
  INFO: active TLS scan starting — 1 network(s)
  INFO: scan complete — 12 asset(s) found
  ```

  Press **Ctrl+C** to stop watching logs. The probe keeps running in the background.

  ---

  ### Useful commands

  | Command | What it does |
  |---|---|
  | `docker compose up -d` | Start the probe in the background |
  | `docker compose logs -f` | Stream probe logs |
  | `docker compose down` | Stop and remove the container |
  | `docker compose pull && docker compose up -d` | Update to the latest image |
  | `docker compose restart` | Restart after editing config.yaml |

  ---

  ## Full config.yaml reference

  ```yaml
  probe:
    name: "datacenter-east"         # Label shown in CryptoSight inventory
    apiKey: "csp_..."               # API key from the Probes page (keep secret)
    endpoint: "https://..."         # CryptoSight base URL, no trailing slash

  scan:
    networks: []                    # Required for discovery; e.g. ["192.168.1.0/24", "10.0.0.0/8"]
    ports: [443, 8443, 636, 5671, 8080, 9200, 3269]
    concurrency: 50                 # max simultaneous TLS connections
    timeoutSeconds: 5               # per-host connect + handshake timeout
    schedule: "0 2 * * *"          # 5-field cron expression; omit for one-shot

  certStore:
    enabled: false                  # set true to walk local PEM/DER cert directories
    paths:
      - /etc/ssl/certs              # directories to scan (Linux defaults)
      - /etc/pki/tls/certs

  mode:
    activeScan: true                # active TLS scanner (recommended — leave true)
    passiveSniffer: false           # passive pcap capture (see section below)

  sniffer:                          # only used when mode.passiveSniffer: true
    interface: "eth0"               # network interface to capture
    bpfFilter: "tcp port 443 or tcp port 8443"
    flushIntervalSeconds: 60
    maxBufferAssets: 500
  ```

  ---

  ## Passive sniffer (optional)

  The sniffer captures live TLS handshakes off the wire — showing what crypto is
  actually *in use*, including short-lived internal connections invisible to cert stores.

  **Requires:** Docker with `NET_RAW`/`NET_ADMIN` capabilities and `network_mode: host`.

  **Docker Desktop for Windows:** supported — the probe auto-detects `eth0` and captures WSL2 VM traffic. Set `network_mode: host` in docker-compose.yml for best results.
  **Docker Desktop for Mac:** not supported (VM networking prevents packet capture). Deploy on a Linux host.

  **To enable:**

  1. In `config.yaml`, set:
     ```yaml
     mode:
       passiveSniffer: true

     sniffer:
       interface: "eth0"   # run "ip link" on the host to list interfaces
     ```

  2. In `docker-compose.yml`, uncomment the three blocks:
     ```yaml
     cap_add:
       - NET_ADMIN
       - NET_RAW
     security_opt:
       - apparmor:unconfined
     network_mode: host
     ```

  3. Restart: `docker compose down && docker compose up -d`

  ---

  ## Kubernetes (DaemonSet)

  A DaemonSet runs one probe per node. With `hostNetwork: true`, each pod shares
  the node's network namespace for cluster-wide TLS visibility.

  **kubectl + kustomize:**

  ```bash
  git clone https://github.com/WaltPdub/cryptosight-probe.git
  cd cryptosight-probe

  # Fill in your API key and endpoint
  vim k8s/configmap.yaml

  kubectl apply -k k8s/
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

  | Helm value | Default | Description |
  |---|---|---|
  | `probe.apiKey` | — | Your API key (use `probe.existingSecret` for production) |
  | `probe.endpoint` | — | Your CryptoSight URL |
  | `probe.namePrefix` | `k8s` | Per-node probe name prefix (`<prefix>-<nodeName>`) |
  | `sniffer.interface` | `eth0` | Interface to capture |
  | `resources.limits.memory` | `512Mi` | Increase on busy nodes |

  ---

  ## Troubleshooting

  | Symptom | Fix |
  |---|---|
  | `pull access denied for cryptosight/probe` | You have the old `docker-compose.yml`. Re-download it (Step 2 above) and retry. |
  | `401 Unauthorized` | Wrong `apiKey` — regenerate it on the Probes page and update config.yaml. |
  | `404 Not Found` | Wrong `endpoint` URL, or the probe was deleted from CryptoSight. |
  | `Error: open /config/config.yaml: no such file` | Missing config.yaml in the same folder as docker-compose.yml. |
  | No assets discovered | `scan.networks` is empty — add at least one CIDR range and restart. |
  | All hosts time out | Increase `scan.timeoutSeconds` or reduce `scan.concurrency` in config.yaml. |
  | `Error parsing config.yaml` | YAML indentation error — YAML requires spaces, not tabs. |
  | Sniffer: `Operation not permitted` | Add `cap_add: [NET_ADMIN, NET_RAW]` to docker-compose.yml. |
  | Sniffer: `No such device` | Wrong interface name — run `ip link` on the host to list them. |
  | Sniffer captures nothing | Set `network_mode: host` in docker-compose.yml — bridge mode only sees container traffic. |
  | Sniffer not available | Docker Desktop for Mac is not supported. On Windows, the probe auto-detects `eth0` (WSL2 VM traffic). For full host capture deploy on a native Linux host. |

  ---

  ## How assets reach the inventory

  ```
  probe → POST /api/probes/ingest (Bearer csp_...)
           ↓
           server: validate → deduplicate → upsert
           source = "probe:<name>"
  ```

  The same certificate found by the probe and a cloud sensor (e.g. Vault) deduplicates
  to one inventory row — the probe observation adds a location, not a duplicate asset.

  ---

  ## Security notes

  - The probe process runs as a **non-root** user inside the container.
  - The API key is read from `config.yaml` at startup — never passed as a CLI argument or environment variable.
  - The active scanner intentionally accepts invalid/expired certificates — an expired cert is still a crypto asset that belongs in the inventory.
  - **Never commit `config.yaml` to source control** — it contains your API key.
  - To rotate the API key: generate a new one on the Probes page, update `apiKey` in config.yaml, and run `docker compose restart`.
