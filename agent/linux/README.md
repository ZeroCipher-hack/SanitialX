# SanitialX Linux Agent

The Linux agent is a stdlib-only Python client for the SanitialX backend. It enrolls once, stores its endpoint token locally with mode `0600`, reports heartbeat telemetry, uploads Debian software inventory, and forwards durable JSONL-spooled events into the existing SanitialX detection pipeline.

## 1. Install

```bash
sudo mkdir -p /opt/sanitialx-agent /var/lib/sanitialx-agent
sudo cp sanitialx_agent.py /opt/sanitialx-agent/
sudo chmod 0755 /opt/sanitialx-agent/sanitialx_agent.py
```

## 2. Enroll

Use the backend enrollment key (`SENTINELX_API_KEY`) only for bootstrap enrollment. The returned per-agent token is stored locally and used afterward.

```bash
sudo SANITIALX_ENROLLMENT_KEY='<enrollment-key>' \
  python3 /opt/sanitialx-agent/sanitialx_agent.py \
  --server http://SERVER:8000/api/v1 enroll
```

The state directory defaults to `/var/lib/sanitialx-agent` and contains:

- `agent-id` — stable endpoint identity
- `agent-token` — endpoint credential, mode `0600`
- `events.jsonl` — durable unsent event spool

## 3. Test manually

```bash
sudo python3 /opt/sanitialx-agent/sanitialx_agent.py --server http://SERVER:8000/api/v1 heartbeat
sudo python3 /opt/sanitialx-agent/sanitialx_agent.py --server http://SERVER:8000/api/v1 inventory
sudo python3 /opt/sanitialx-agent/sanitialx_agent.py --server http://SERVER:8000/api/v1 event linux_test 'SanitialX agent test event' --severity LOW
sudo python3 /opt/sanitialx-agent/sanitialx_agent.py --server http://SERVER:8000/api/v1 flush
```

## 4. Run continuously with systemd

```bash
sudo cp sanitialx-agent.service /etc/systemd/system/
printf 'SANITIALX_SERVER_URL=http://SERVER:8000/api/v1\n' | sudo tee /etc/sanitialx-agent.env
sudo chmod 0600 /etc/sanitialx-agent.env
sudo systemctl daemon-reload
sudo systemctl enable --now sanitialx-agent
sudo systemctl status sanitialx-agent
```

Heartbeat is sent every 30 seconds. The backend default timeout is 120 seconds, after which an enrolled endpoint is automatically marked `OFFLINE`. A new valid heartbeat returns it to `ONLINE`.

## Security notes

- Use HTTPS outside a trusted local development network.
- Never distribute the enrollment key as a long-lived agent credential.
- Each agent gets its own high-entropy token; the backend stores only its SHA-256 hash.
- Re-enrollment rotates the endpoint token.
- The client applies exponential retry and keeps unsent events on disk until accepted.
