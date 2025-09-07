const { ethers } = require("ethers");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");
const chalk = require("chalk");

dotenv.config();

// === CONFIG ===
// List of public RPCs for Celo.
const RPCS = [
  "https://rpc.ankr.com/celo",
  "https://celo.drpc.org",
  "https://forno.celo.org",
  "https://1rpc.io/celo"
];
const GAS_LIMIT = 21000;
const keysFile = "key.txt";
let lastKey = null;

// --- Load keys from file ---
const PRIVATE_KEYS = fs.readFileSync(keysFile, "utf-8")
  .split("\n")
  .map(line => line.trim())
  .filter(line => line.length > 0);

// --- Wallet Persona Management ---
const personaFile = "personas.json";
let walletProfiles = {};
let lastPersonaSave = 0;
const PERSONA_SAVE_DEBOUNCE_MS = 5_000; // coalesce multiple writes into one

function loadPersonas() {
  if (fs.existsSync(personaFile)) {
    try {
      walletProfiles = JSON.parse(fs.readFileSync(personaFile, "utf-8"));
      console.log(chalk.cyan("🎭 Loaded existing personas"));
    } catch (e) {
      console.error(chalk.bgRed.white.bold("❌ Error parsing personas.json, starting fresh."));
      walletProfiles = {};
    }
  }
}

// Debounced save to avoid frequent blocking disk writes
function savePersonas() {
  try {
    const now = Date.now();
    if (now - lastPersonaSave < PERSONA_SAVE_DEBOUNCE_MS) {
      // schedule a final write shortly
      setTimeout(() => {
        try { fs.writeFileSync(personaFile, JSON.stringify(walletProfiles, null, 2)); lastPersonaSave = Date.now(); }
        catch (e) { console.error("failed saving personas:", e.message); }
      }, PERSONA_SAVE_DEBOUNCE_MS);
      return;
    }
    fs.writeFileSync(personaFile, JSON.stringify(walletProfiles, null, 2));
    lastPersonaSave = now;
  } catch (e) {
    console.error("failed saving personas:", e.message);
  }
}

function ensurePersona(wallet) {
  if (!walletProfiles[wallet.address]) {
    walletProfiles[wallet.address] = {
      idleBias: Math.random() * 0.25,
      pingBias: Math.random() * 0.25,
      minAmount: 0.00005 + Math.random() * 0.0001,
      maxAmount: 0.015 + Math.random() * 0.005,
      // NEW TRAITS
      activeHours: [6 + Math.floor(Math.random() * 6), 22], // e.g. 06:00-22:00 UTC
      cooldownAfterFail: 60 + Math.floor(Math.random() * 180), // 1-4 min
      avgWait: 60 + Math.floor(Math.random() * 120), // base wait time 1-3 min
      retryBias: Math.random() * 0.5, // 0-50% chance to retry
      // dynamic per-wallet nonce retirement
      maxNonce: 520 + Math.floor(Math.random() * 100),
      // failure tracking
      failCount: 0,
      lastFailAt: null
    };
    savePersonas();
  }
  return walletProfiles[wallet.address];
}

// --- Dynamic Log File Management (Daily Rotation) ---
// This function returns the log file path for the current day.
function getLogFile() {
  const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD format
  return path.join(__dirname, `tx_log_${today}.csv`);
}

// This function initializes the log file with a header if it doesn't exist.
function initLogFile() {
  const logFile = getLogFile();
  if (!fs.existsSync(logFile)) {
    fs.writeFileSync(
      logFile,
      "timestamp,wallet,tx_hash,nonce,gas_used,gas_price_gwei,fee_celo,status,action\n"
    );
  }
  return logFile;
}

// --- Tx Log Buffer ---
let txBuffer = [];
const FLUSH_INTERVAL = 300 * 1000;
function bufferTxLog(entry) {
  txBuffer.push(entry);
}
function flushTxLog() {
  if (txBuffer.length === 0) return;
  const logFile = initLogFile();
  fs.appendFileSync(logFile, txBuffer.join("\n") + "\n");
  console.log(chalk.gray(`📝 Flushed ${txBuffer.length} tx logs to disk`));
  txBuffer = [];
}
// Periodic flusher
setInterval(flushTxLog, FLUSH_INTERVAL);

// --- Pick random key (with small chance of reusing last key) ---
// Provides a more "human-like" key selection by sometimes re-using the last key.
function pickRandomKey() {
  if (lastKey && Math.random() < 0.2) return lastKey;
  const idx = Math.floor(Math.random() * PRIVATE_KEYS.length);
  lastKey = PRIVATE_KEYS[idx];
  return lastKey;
}

// --- Provider without proxy ---
function getProvider(rpcUrl) {
  const network = {
    chainId: 42220,
    name: "celo"
  };
  return new ethers.JsonRpcProvider(rpcUrl, network);
}

/**
 * Attempts to connect to an RPC endpoint.
 * @returns {Promise<{provider: ethers.JsonRpcProvider, url: string}|null>} The working provider and its URL, or null if all fail.
 */
async function tryProviders() {
  console.log(chalk.hex("#00FFFF").bold("🔍 Searching for a working RPC endpoint..."));
  for (const url of RPCS) {
    try {
      const provider = getProvider(url);
      const network = await Promise.race([
        provider.getNetwork(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000))
      ]);
      console.log(chalk.hex("#00FF7F").bold(`✅ Connected: ${url}, Chain ID: ${network.chainId}`));
      return { provider, url };
    } catch (e) {
      console.log(chalk.hex("#FF5555").bold(`❌ Failed to connect to ${url}: ${e.message}`));
    }
  }
  return null;
}

/**
 * Iterates through the list of RPCs and returns the first one that successfully connects.
 * @returns {Promise<{provider: ethers.JsonRpcProvider, url: string}>} The working provider and its URL.
 */
async function getWorkingProvider() {
  return await tryProviders();
}

function randomDelay(minSec, maxSec) {
  const ms = (Math.floor(Math.random() * (maxSec - minSec + 1)) + minSec) * 1000;
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isWithinActiveHours(profile) {
  const nowUTC = new Date().getUTCHours();
  return nowUTC >= profile.activeHours[0] && nowUTC <= profile.activeHours[1];
}

async function sendTx(wallet, provider, profile, url) {
  try {
    if (Math.random() < profile.idleBias) {
      console.log(chalk.hex("#808080").italic("\n😴 Persona idle mode, skipping this cycle..."));
      return;
    }

    const balance = await provider.getBalance(wallet.address);
    await randomDelay(2, 4);

    const walletNonce = await provider.getTransactionCount(wallet.address);
    await randomDelay(2, 4); // Another short delay

    const maxNonce = profile.maxNonce;
    if (walletNonce >= maxNonce) {
      console.log(chalk.bgYellow.black.bold(`\n🟡 Wallet: ${wallet.address} nonce ${walletNonce} >= ${maxNonce}. Skipping.`));
      return;
    }

    console.log(chalk.hex("#1E90FF").bold.underline(`\n🎲 Wallet: ${wallet.address}`));
    console.log(chalk.hex("#1E90FF").bold(`Using RPC: ${url}`));
    console.log(chalk.hex("#FFD700").bold(`Balance: ${ethers.formatEther(balance)} CELO`));
    console.log(chalk.hex("#FFD700").bold(`Nonce: ${walletNonce}`));

    if (balance < ethers.parseEther("0.01")) {
      console.log(chalk.hex("#FFA500").bold("⚠️ Not enough balance, skipping..."));
      return;
    }

    // === Decide action: normal send vs ping ===
    let action = "normal";
    let value;
    if (Math.random() < profile.pingBias) {
      action = "ping";
      value = 0n; // 0 CELO, just burns gas
    } else {
      const amount = profile.minAmount + Math.random() * (profile.maxAmount - profile.minAmount);
      value = ethers.parseEther(amount.toFixed(6));
    }

    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: value,
      gasLimit: GAS_LIMIT
    });

    console.log(chalk.hex("#7FFF00").bold(`✅ Sent tx: ${tx.hash}`));
    // Safely log the gas price, accounting for EIP-1559 transactions.
    const gasPrice = tx.gasPrice ?? tx.maxFeePerGas ?? 0n;
    if (gasPrice > 0n) {
      console.log(chalk.hex("#FF69B4").bold(`⛽ Gas Price (RPC): ${ethers.formatUnits(gasPrice, "gwei")} gwei`));
    }
    console.log(chalk.dim(`Explorer link: https://celoscan.io/tx/${tx.hash}`));

    // Initialize variables outside of the try block to ensure scope
    let status = "pending", gasUsed = "", feeCELO = "", gasPriceGwei = "", txNonce = tx.nonce;

    try {
      // Use Promise.race with a timeout that resolves to null
      const receipt = await Promise.race([
        tx.wait(),
        new Promise(resolve => setTimeout(() => resolve(null), 30000)) // returns null on timeout
      ]);

      if (receipt) {
        // Only access receipt properties if it's not null/undefined
        status = "confirmed";
        // Safely handle potentially missing gasPrice or gasUsed
        const gasPriceUsed = receipt?.effectiveGasPrice ?? receipt?.gasPrice ?? 0n;
        gasUsed = (receipt?.gasUsed ?? 0n).toString();
        gasPriceGwei = ethers.formatUnits(gasPriceUsed, "gwei");
        feeCELO = ethers.formatEther(gasPriceUsed * (receipt?.gasUsed ?? 0n));

        console.log(chalk.bgGreen.white.bold("🟢 Confirmed!"));
        console.log(`   Nonce: ${txNonce}`);
        console.log(chalk.hex("#ADFF2F").bold(`   Gas Used: ${gasUsed}`));
        console.log(chalk.hex("#FFB6C1").bold(`   Gas Price: ${gasPriceGwei} gwei`));
        console.log(chalk.hex("#FFD700").bold(`   Fee Paid: ${feeCELO} CELO`));
      } else {
        console.log(chalk.bgYellow.white.bold("🟡 No confirmation in 30s, moving on..."));
        status = "timeout";
      }
    } catch (err) {
      console.error(chalk.bgRed.white.bold("❌ Error fetching receipt:", err.message));
      status = "error";
    }

    // === Buffer to CSV (daily rotation) ===
    const line = [
      new Date().toISOString(),
      wallet.address,
      tx.hash,
      txNonce,
      gasUsed,
      gasPriceGwei,
      feeCELO,
      status,
      action
    ].join(",");
    bufferTxLog(line);

  } catch (err) {
    console.error(chalk.bgRed.white.bold("❌ Error in sendTx:", err.message));
    throw err; // Re-throw to be caught by safeSendTx for cooldown logic
  }
}

async function safeSendTx(wallet, provider, profile, url) {
  try {
    await sendTx(wallet, provider, profile, url);
  } catch (err) {
    console.log(chalk.hex("#FFA500").bold("⚠️ Transaction failed. Checking persona retry bias..."));

    // NEW LOGIC: Check retry bias and apply cooldown
    if (Math.random() > profile.retryBias) {
      console.log(chalk.hex("#FF8C00")(`⏸ Persona ${wallet.address} cooling down after fail...`));
      // Add a small jitter to the cooldown period
      const cooldownSec = profile.cooldownAfterFail + Math.floor(Math.random() * 60);
      await randomDelay(cooldownSec, cooldownSec);
      return;
    }

    console.log(chalk.hex("#FFA500").bold("⚠️ Retrying after error..."));
    await randomDelay(5, 10);
    try { await sendTx(wallet, provider, profile, url); } catch (retryErr) {
      console.error(chalk.bgRed.white.bold("❌ Error on retry:", retryErr.message));
    }
  }
}

async function loop() {
  loadPersonas(); // Load personas at the start of the loop
  while (true) {
    // === NEW LOGIC: Retry loop for RPC connection ===
    let provider = null;
    let url = null;
    while (!provider) {
      const providerResult = await getWorkingProvider();
      if (providerResult) {
        provider = providerResult.provider;
        url = providerResult.url;
      } else {
        console.log(chalk.hex("#FF8C00").bold("🚫 All RPCs failed to connect. Retrying in 10 seconds..."));
        await randomDelay(10, 15);
      }
    }
    // === END NEW LOGIC ===

    const key = pickRandomKey();
    const wallet = new ethers.Wallet(key, provider);
    const profile = ensurePersona(wallet);

    // Check if the wallet is within its active hours
    if (!isWithinActiveHours(profile)) {
      const sleepSec = 600 + Math.floor(Math.random() * 600); // 10–20 min idle
      console.log(chalk.gray(`🛌 Wallet ${wallet.address} is outside active hours, sleeping ${sleepSec}s`));
      await randomDelay(sleepSec, sleepSec);
      continue;
    }

    // Execute the transaction logic, including retries
    await safeSendTx(wallet, provider, profile, url);

    // NEW LOGIC: Use persona's avgWait for the wait loop
    let waitSec = Math.floor(profile.avgWait * (0.8 + Math.random() * 0.4));

    console.log(chalk.hex("#00CED1").italic.bold(`⏳ Waiting ${waitSec}s before next tx...`));
    await randomDelay(waitSec, waitSec);
  }
}

loop();

// ensure flush/persona save on termination/unhandled
process.on("SIGINT", () => { console.log("SIGINT"); flushTxLog(); savePersonas(); process.exit(); });
process.on("SIGTERM", () => { console.log("SIGTERM"); flushTxLog(); savePersonas(); process.exit(); });
process.on("exit", () => { flushTxLog(); savePersonas(); });
process.on("unhandledRejection", (r) => { console.error("unhandledRejection:", r); flushTxLog(); savePersonas(); });
