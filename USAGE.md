# 📘 Usage Guide – Celo Wallet Activity Simulator

This document explains how to set up and use the **Celo Wallet Activity Simulator**, along with details of the **persona system** and log formats.

---

## 🛠️ Setup

1. **Clone the repo**

   ```bash
   git clone https://github.com/your-username/celo-wallet-simulator.git
   cd celo-wallet-simulator
   npm install
   ```

2. **Add wallet keys**

   * Create a file named `key.txt` in the root directory.
   * Place **one private key per line**:

     ```
     0xabc123...
     0xdef456...
     ```

3. **Run the simulator**

   ```bash
   node index.js
   ```

4. **Check logs**

   * Transaction logs are saved as CSV files:

     ```
     tx_log_2025-09-07.csv
     ```

---

## 🎭 Persona System

Each wallet is assigned a **persona** stored in `personas.json`.
A persona defines how that wallet behaves over time.

### Fields

| Field               | Description                                                 | Example                  |
| ------------------- | ----------------------------------------------------------- | ------------------------ |
| `idleBias`          | Probability of skipping a cycle (wallet “rests”).           | `0.12` (12% chance)      |
| `pingBias`          | Probability of sending a **zero-value tx** (gas burn only). | `0.18`                   |
| `minAmount`         | Minimum CELO per normal tx.                                 | `0.00007`                |
| `maxAmount`         | Maximum CELO per normal tx.                                 | `0.019`                  |
| `activeHours`       | Time window (UTC) when the wallet is “awake.”               | `[8, 22]`                |
| `cooldownAfterFail` | Seconds to sleep after a failed tx.                         | `180`                    |
| `avgWait`           | Base wait time between tx (randomized ±20%).                | `120`                    |
| `retryBias`         | Probability of retrying after a failure.                    | `0.4`                    |
| `maxNonce`          | Maximum nonce allowed for this wallet before retirement.    | `590`                    |
| `failCount`         | Internal counter for failures.                              | `2`                      |
| `lastFailAt`        | Last failure timestamp.                                     | `"2025-09-07T20:15:00Z"` |

> Personas evolve naturally as they’re saved/updated over multiple runs.

---

## 📝 Log Format

Transactions are written to **daily CSV logs**.

### Example log line

```csv
timestamp,wallet,tx_hash,nonce,gas_used,gas_price_gwei,fee_celo,status,action
2025-09-07T20:30:25Z,0x1234...,0xabcd...,42,21000,2.5,0.0000525,confirmed,normal
```

### Fields

* **timestamp** – ISO UTC time of the tx
* **wallet** – wallet address
* **tx\_hash** – hash of the sent tx
* **nonce** – wallet nonce at tx time
* **gas\_used** – gas consumed (usually 21000 for transfers)
* **gas\_price\_gwei** – gas price in gwei
* **fee\_celo** – total fee paid in CELO
* **status** – `confirmed`, `timeout`, `error`, `pending`
* **action** – `normal` (value tx), `ping` (0-value), or other custom actions

---

## 📌 Example Workflow

* Wallet wakes up at 08:00 UTC.
* Skips 10% of cycles due to `idleBias`.
* Sends mostly small transfers (0.0001–0.01 CELO).
* Occasionally sends 0 CELO pings (`pingBias`).
* If a tx fails, waits 3–5 minutes before retrying.
* Stops sending tx when nonce > `maxNonce`.

---

## 🚀 Advanced Options

* **Custom RPCs**
  Add or replace RPC URLs in `index.js` under `RPCS`.
* **Persona Tweaks**
  Manually edit `personas.json` to fine-tune wallet behavior.
* **Log Analysis**
  Import CSV logs into Excel, Python, or Grafana for visualization.

---

## ⚠️ Disclaimer

This simulator is for **educational and development purposes only**.
It is intended to help Celo developers and infrastructure teams test **RPC reliability, wallet activity patterns, and logging pipelines**.
