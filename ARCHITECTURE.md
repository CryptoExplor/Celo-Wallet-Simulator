# 🏗️ Architecture – Celo Wallet Activity Simulator

This document explains the **internal design** of the simulator, covering personas, execution flow, and logging.

---

## 🔹 High-Level Overview

```
+-----------------+       +-----------------+       +-----------------+
|   Personas DB   | --->  |   Simulation    | --->  |   RPC Endpoints |
|  (personas.json)|       |   Loop Engine   |       |   (Celo RPCs)   |
+-----------------+       +-----------------+       +-----------------+
         |                         |                         |
         |                         v                         |
         |                 +-----------------+               |
         |                 |   Tx Generator  |               |
         |                 +-----------------+               |
         |                         |                         |
         v                         v                         v
+-----------------+       +-----------------+       +-----------------+
| Configurable    | --->  | Transaction Log | --->  |   CSV Export    |
| Parameters      |       |   (memory buf)  |       | (tx_log_*.csv)  |
+-----------------+       +-----------------+       +-----------------+
```

---

## 🎭 Personas

Each wallet has a **persona**, stored in `personas.json`.
Personas define:

* **Behavioral biases** (`idleBias`, `pingBias`)
* **Transaction ranges** (`minAmount`, `maxAmount`)
* **Active hours** (UTC windows)
* **Error handling** (`cooldownAfterFail`, `retryBias`)
* **Lifecycle** (`maxNonce`, `failCount`)

This creates **organic, wallet-specific activity patterns**.

---

## 🔄 Execution Loop

The simulator runs in **per-wallet cycles**:

1. **Check active hours**

   * Skip if outside `activeHours`.

2. **Apply persona biases**

   * Random chance to idle (`idleBias`).
   * Random chance to send **0-value tx** (`pingBias`).

3. **Generate transaction**

   * Choose recipient from cache.
   * Pick amount within `[minAmount, maxAmount]`.
   * Add gas checks and random delays.

4. **Send via RPC**

   * Rotate through RPC endpoints.
   * Retry if failure, respecting cooldown rules.

5. **Log result**

   * Save `tx_hash`, gas used, status, fee → CSV.

---

## ⏳ Wait Logic

Instead of a fixed delay, each persona has an **adaptive wait**:

```js
let waitSec = Math.floor(
  profile.avgWait * (0.8 + Math.random() * 0.4)
);
```

* Ensures wait time varies **±20% around avgWait**.
* Prevents uniform activity (more natural).

Example:

* `avgWait = 120s` → range: **96–144s**

---

## 📂 File Structure

```
celo-wallet-simulator/
│── index.js          # Main loop engine
│── personas.json     # Wallet behavior profiles
│── key.txt           # Wallet private keys (1 per line)
│── logs/             # Transaction logs (CSV)
│── USAGE.md          # Usage documentation
│── ARCHITECTURE.md   # Architecture documentation
│── package.json
```

---

## 📝 Logging

Transactions are written to **daily CSV logs**:

* **timestamp** – ISO UTC time
* **wallet** – sender address
* **tx\_hash** – transaction hash
* **nonce** – sender’s nonce
* **gas\_used** – consumed gas
* **gas\_price\_gwei** – gas price in Gwei
* **fee\_celo** – total fee in CELO
* **status** – confirmed, failed, timeout
* **action** – normal, ping

---

## 🚀 Key Features

✅ Persona-driven wallet activity
✅ Natural transaction spacing
✅ Multi-RPC rotation (Celo endpoints)
✅ Configurable via JSON
✅ CSV-based structured logging

---

## ⚠️ Disclaimer

This tool is intended for **development, infra testing, and monitoring use cases** within the Celo ecosystem.
It should **not** be used for spam, abuse, or production financial activity.
