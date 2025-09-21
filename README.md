# ⚡ Celo Wallet Simulator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)    [![Node.js](https://img.shields.io/badge/node-%3E%3D18-green)](https://nodejs.org/)     [![CI](https://github.com/CryptoExplor/Celo-Wallet-Simulator/actions/workflows/node.yml/badge.svg)](https://github.com/CryptoExplor/Celo-Wallet-Simulator/actions)     [![GitHub stars](https://img.shields.io/github/stars/CryptoExplor/Celo-Wallet-Simulator?style=social)](https://github.com/CryptoExplor/Celo-Wallet-Simulator/stargazers)

A lightweight **wallet activity simulator** for the **Celo blockchain**, designed for:

* 🔹 **Infrastructure testing** (RPCs, nodes, endpoints)
* 🔹 **Monitoring transaction throughput**
* 🔹 **Researching organic wallet behavior**
* 🔹 **Developer tooling & analytics**

---

## 📦 Features

* ✅ **In-memory encrypted private keys** (AES-256-GCM) — private keys are kept encrypted in memory and decrypted only when required for signing.
* ✅ **Multi-master key support & rotation** — `MASTER_KEY` with optional `BACKUP_KEYS` for recovery and key rotation.
* ✅ **Persona-driven wallet behavior** (`personas.json`) — idleBias, pingBias, activeHours, avgWait, retryBias, maxNonce, and device-agent.
* ✅ **Device-agent support** — per-wallet `User-Agent` and simulated latency to diversify fingerprints.
* ✅ **Configurable wait logic** — adaptive/random spacing to mimic organic activity.
* ✅ **Multi-RPC rotation & proxy support** — automatic failover across Celo RPC endpoints; supports HTTP(S) and SOCKS proxies (`proxy.txt`).
* ✅ **Adaptive activity patterns** — dynamic idleBias based on recent success/failure history.
* ✅ **Structured CSV logging** — daily rotated `tx_log_YYYY-MM-DD.csv` with buffered flushes.
* ✅ **Graceful shutdown** — signal handlers flush logs and persist personas.

---

## 🚀 Quick Start

1. **Clone the repo**

   ```bash
   git clone https://github.com/CryptoExplor/Celo-Wallet-Simulator.git
   cd Celo-Wallet-Simulator
   npm install
   ```

2. **Configure environment**

   Create a local `.env` (for testing only — do NOT commit) with at minimum:

   ```bash
   PRIVATE_KEYS="0xabc...\n0xdef..."       # one key per line
   MASTER_KEY="your_master_passphrase"
   BACKUP_KEYS="oldMaster1,oldMaster2"     # optional
   ```

   Or set these as OS-level environment variables (recommended for production).

3. **(Optional) Add legacy key file**

   If you prefer legacy workflow, create `key.txt` with one private key per line — but `index.js` reads `PRIVATE_KEYS` env by default.

4. **Run the simulator**

   ```bash
   node index.js
   ```

5. **Stop gracefully**

   * Press `Ctrl+C` — the process will flush logs and save persona state before exit.

---

## 📘 Documentation

* 📄 [Usage Guide](./USAGE.md) – setup, personas, logging, workflow
* 📄 [Architecture](./ARCHITECTURE.md) – system design & internals

---

## 🧩 Configuration & Files

* `index.js` — main runtime engine (encryption, personas, RPC/proxy logic, tx loop).
* `personas.json` — persona defaults (created automatically if missing). The simulator also supports encrypted persona storage.
* `inactive.json` — stores addresses marked outside their active hours (can be encrypted on disk if enabled).
* `proxy.txt` — optional: one proxy URL per line (`http(s)://host:port` or `socks5://host:port`).
* `key.txt` — legacy: one private key per line (not required if using `PRIVATE_KEYS` env).
* `tx_log_YYYY-MM-DD.csv` — daily CSV logs with header: `timestamp,wallet,tx_hash,nonce,gas_used,gas_price_gwei,fee_celo,status,action`.

### Persona format (example)

Personas are stored as an object keyed by wallet address. Example:

```json
{
  "0xabc...": {
    "idleBias": 0.12,
    "pingBias": 0.06,
    "minAmount": 0.0001,
    "maxAmount": 0.01,
    "activeHours": [2, 22],
    "cooldownAfterFail": 90,
    "avgWait": 45,
    "retryBias": 0.2,
    "maxNonce": 560,
    "failCount": 0,
    "lastFailAt": null,
    "deviceAgent": { "userAgent": "Chrome/102.0 (Windows NT 10.0)", "latency": 120 }
  }
}
```

---

## 🔒 Security Notes

* **MASTER\_KEY** encrypts private keys in memory and is required at process start. Provide it via OS-level secrets or a secure vault in production.
* **BACKUP\_KEYS** allow decrypting older encrypted blobs after key rotation. The script attempts decryption with all provided master keys.
* **Session salt** is used for stronger ephemeral key derivation. If you require persistent encrypted artifacts across runs, use per-key persistent salts stored with the ciphertext.
* **Encrypted personas/inactive storage**: the simulator supports encrypting `personas.json` and `inactive.json` on write and decrypting on load — enable this to protect persona metadata at rest.
* **Never commit** `.env`, `key.txt`, or any file containing real private keys to version control.
* Consider using HashiCorp Vault, AWS Secrets Manager, or similar for production secrets.

---

## 🕵️ Device Agent & Fake Latency

* Each persona can include a `deviceAgent` object containing a `userAgent` string and a `latency` value (ms). The simulator uses `userAgent` when making HTTP/RPC calls where custom headers are supported and applies `latency` as a simulated network delay before/after RPC calls to diversify network footprints.
* Device agents are persisted in personas (and can be encrypted on disk) so wallets keep consistent fingerprinting unless rotated deliberately.

---

## ⚙️ Adaptive Activity Patterns

* The simulator keeps simple success/failure counters per persona (`txSuccessCount`, `txFailCount`) and uses those to **adjust `idleBias` dynamically**.
* If a wallet experiences repeated failures, `idleBias` increases to reduce activity (saving gas and avoiding repeated failures). When success rate improves, `idleBias` lowers to resume normal activity.

---

## 📈 Logging & Observability

* Transaction logs are buffered and flushed to daily CSV files every 5 minutes (configurable).
* Consider integrating metrics or a dashboard (Prometheus / Grafana) for real-time monitoring and alerts (RPC failures, wallet depletion, repeated tx failures).

---

## 🛠️ Extensibility & Next Steps

Suggested improvements:

* Encrypted persona & inactive storage (implemented/optional)
* Persistent per-key salts for long-term encrypted artifacts
* Dashboard & metrics for live monitoring
* Stable proxy-per-wallet assignment to simulate consistent geolocation

---

## 🤝 Contributing

Contributions welcome. Fork → branch → PR. Include tests and documentation for runtime changes.

---

## ⚠️ Disclaimer

This tool is for research, testing, and education. Do **not** use it for spam, Sybil attacks, or behavior that violates network terms. Use testnets wherever possible.

---

## 📜 License

Licensed under the terms in the [LICENSE](LICENSE) file.
