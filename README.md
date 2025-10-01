# ⚡ Celo Wallet Simulator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-green)](https://nodejs.org/)
[![CI](https://github.com/CryptoExplor/Celo-Wallet-Simulator/actions/workflows/node.yml/badge.svg)](https://github.com/CryptoExplor/Celo-Wallet-Simulator/actions)
[![GitHub stars](https://img.shields.io/github/stars/CryptoExplor/Celo-Wallet-Simulator?style=social)](https://github.com/CryptoExplor/Celo-Wallet-Simulator/stargazers)

A lightweight **wallet activity simulator** for the **Celo blockchain**, designed for:

* 🔹 **Infrastructure testing** (RPCs, nodes, endpoints)
* 🔹 **Monitoring transaction throughput**
* 🔹 **Researching organic wallet behavior**
* 🔹 **Developer tooling & analytics**

---

## 📦 Features

* ✅ **In-memory encrypted private keys** (AES-256-GCM): Private keys are encrypted in memory and decrypted only when signing transactions.
* ✅ **Multi-master key support & rotation**: `MASTER_KEY` with optional `BACKUP_KEYS` for recovery and key rotation.
* ✅ **Persona-driven wallet behavior** (`personas.json`): Configurable parameters include `idleBias`, `pingBias`, `activeHours`, `avgWait`, `retryBias`, `minAmount`, `maxAmount`, `cooldownAfterFail`, `maxNonce`, and `device-agent`.
* ✅ **Device-agent support**: Per-wallet `User-Agent` and simulated latency for fingerprint diversity.
* ✅ **Configurable wait logic**: Adaptive/random spacing to mimic organic activity.
* ✅ **Multi-RPC rotation & proxy support**: Automatic failover across Celo RPC endpoints; supports HTTP(S) and SOCKS proxies (`proxy.txt`).
* ✅ **Proxy auto-refresh**: Proxies reload every **15 minutes** without restart.
* ✅ **Inactive wallet refresh**: Wallets marked inactive are refreshed every **30 minutes** and re-activated once their active hours are reached.
* ✅ **Adaptive activity patterns**: Dynamic `idleBias` adjusting to success/failure rates.
* ✅ **Transaction retry logic**: Governed by persona `retryBias` and cooldown parameters, with randomized wait times.
* ✅ **Structured CSV logging**: Daily rotated `tx_log_YYYY-MM-DD.csv` with buffered flushes.
* ✅ **Log retention & cleanup**: Old logs (older than 3 days) auto-deleted. Supports `--clear-logs` flag for full cleanup.
* ✅ **Resource & error monitoring**: Logs memory usage periodically; robust uncaught error handling.
* ✅ **Graceful shutdown**: Signal handlers flush logs and persist persona state on exit.

---

## 🚀 Quick Start

1. **Clone the repository**

   ```bash
   git clone https://github.com/CryptoExplor/Celo-Wallet-Simulator.git
   cd Celo-Wallet-Simulator
   npm install
   ```

2. **Configure environment**

   Create `.env` (for testing only — do NOT commit):

   ```bash
   PRIVATE_KEYS="0xabc...\n0xdef..."       # one key per line
   MASTER_KEY="your_master_passphrase"
   BACKUP_KEYS="oldMaster1,oldMaster2"     # optional
   ```

   Or set them as OS-level environment variables (recommended for production).

3. **(Optional) Add legacy key file**

   Create `key.txt` with one private key per line (optional — overridden by `PRIVATE_KEYS`).

4. **Run the simulator**

   ```bash
   node index.js
   ```

5. **Stop gracefully**

   Press `Ctrl+C` — logs will flush, and persona state will persist.

---

## 🧩 Configuration & Files

* `index.js` — main runtime engine (encryption, personas, RPC/proxy logic, tx loop).
* `personas.json` — persona defaults (auto-created if missing); supports encrypted storage.
* `inactive.json` — stores addresses outside active hours (optional encryption).
* `proxy.txt` — optional: one proxy URL per line (`http(s)://host:port` or `socks5://host:port`).
* `key.txt` — legacy: one private key per line (optional).
* `tx_log_YYYY-MM-DD.csv` — daily logs with: `timestamp,wallet,tx_hash,nonce,gas_used,gas_price_gwei,fee_celo,status,action`.

---

### Persona Example

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
    "deviceAgent": {
      "userAgent": "Chrome/102.0 (Windows NT 10.0)",
      "latency": 120
    }
  }
}
```

---

## 🔒 Security Notes

* **MASTER_KEY** encrypts private keys and is required on startup.
* **BACKUP_KEYS** allow decryption of old encrypted blobs after rotation.
* **Session salt** strengthens ephemeral key derivation; store salts for persistence.
* **Encrypted personas/inactive storage**: optionally encrypt on write/load.
* **Never commit** `.env`, `key.txt`, or any private key files.
* Use secret managers like HashiCorp Vault or AWS Secrets Manager in production.

---

## 🕵️ Device Agent & Fake Latency

* Per-wallet `deviceAgent` settings allow unique `User-Agent` strings and simulated latency to diversify network behavior.
* Device agents are persisted in personas unless rotated manually.

---

## ⚙️ Adaptive Activity Patterns

* Success/failure counters (`txSuccessCount`, `txFailCount`) dynamically adjust `idleBias`.
* Repeated failures increase `idleBias` and reduce activity; success lowers it to normal levels.

---

## 📈 Logging & Observability

* Logs buffered and flushed every 5 minutes.
* Old logs auto-deleted after 3 days; `--clear-logs` flag purges logs.
* Consider metrics dashboards (Prometheus / Grafana) for real-time monitoring.

---

## 🛠️ Extensibility

* Encrypted persona/inactive storage
* Persistent per-key salts
* Dashboard for metrics
* Stable proxy-per-wallet assignment for location simulation

---

## 🤝 Contributing

Fork → branch → PR. Include tests and documentation.

---

## 💝 We Grow Together!

Your contributions help keep this project alive, ad-free, and continuously improving. Consider supporting our development efforts by donating.

**Celo Donation Address:**
`0x1C46ccEA4D62d3eEC4DCE3501aa96d0Ff5FcA954`

---

## ⚠️ Disclaimer

For research, testing, and education only. Avoid spam/Sybil attacks. Use testnets where possible.

---

## 📜 License

Licensed under the terms in the [LICENSE](LICENSE) file.
