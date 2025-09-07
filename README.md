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

✅ Persona-driven wallet behavior (`personas.json`)
✅ Configurable wait logic (adaptive random spacing)
✅ Multi-RPC rotation for Celo endpoints
✅ Structured CSV logging for analysis
✅ JSON-based configuration (no hardcoding)

---

## 🚀 Quick Start

1. **Clone the repo**

   ```bash
   git clone https://github.com/CryptoExplor/Celo-Wallet-Simulator.git
   cd Celo-Wallet-Simulator
   npm install
   ```

2. **Add wallets**

   * Create a `key.txt` file in the root directory.
   * Put **one private key per line**.

3. **Run the simulator**

   ```bash
   node index.js
   ```

4. **View logs**

   * Generated in `tx_log_YYYY-MM-DD.csv` (daily rotation).

---

## 📘 Documentation

📄 [Usage Guide](./USAGE.md) – setup, personas, logging, workflow
📄 [Architecture](./ARCHITECTURE.md) – system design & internals

---

## 📂 Project Structure

```
Celo-Wallet-Simulator/
│── index.js          # Main loop engine
│── personas.json     # Wallet persona configs
│── key.txt           # Wallet private keys (user-supplied)
│── tx_log_*.csv      # Daily transaction logs
│── USAGE.md          # Usage documentation
│── ARCHITECTURE.md   # Architecture documentation
│── package.json
```

---

## ⚠️ Disclaimer

This project is provided for **educational and development purposes only**.
It is intended to support Celo developers and infrastructure teams in:

* Testing RPC endpoints
* Simulating transaction activity
* Analyzing network performance

It should **not** be used for spam, Sybil attacks, or any form of abuse.

---
