import { ethers } from "ethers";
import dotenv from "dotenv";
import * as fs from "fs/promises";
import path from "path";
import chalk from "chalk";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
import { fileURLToPath } from "url";

dotenv.config();

// Define __dirname equivalent for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// --- Key loader (inline, no extra files) ---
let PRIVATE_KEYS = [];
let ALL_WALLETS = [];

// normalize to 0x-prefixed hex string
function normalizeKey(k) {
  if (!k) return null;
  k = String(k).trim();
  if (!k) return null;
  return k.startsWith("0x") ? k : "0x" + k;
}

// Validate by constructing an ethers.Wallet
function isValidPrivateKey(k) {
  try {
    new ethers.Wallet(k);
    return true;
  } catch {
    return false;
  }
}

// Load keys: primary from env PRIVATE_KEYS (comma separated), fallback to keysFile (one-per-line)
async function loadKeysInline({ allowFileFallback = true } = {}) {
  // 1) env var (preferred)
  const env = process.env.PRIVATE_KEYS;
  if (env && env.trim().length > 0) {
    PRIVATE_KEYS = env.split(",").map(normalizeKey).filter(Boolean);
  } else if (allowFileFallback) {
    // 2) fallback to keysFile (async fs from fs/promises is used in this file)
    try {
      const raw = await fs.readFile(keysFile, "utf-8");
      PRIVATE_KEYS = raw.split(/\r?\n/).map(normalizeKey).filter(Boolean);
    } catch (err) {
      // leave PRIVATE_KEYS empty if file not found / unreadable
      PRIVATE_KEYS = [];
    }
  }

  // validate & compute addresses
  const valid = [];
  const addrs = [];
  for (const k of PRIVATE_KEYS) {
    if (!k) continue;
    if (!isValidPrivateKey(k)) {
      console.warn("Ignored invalid private key:", k);
      continue;
    }
    valid.push(k);
    addrs.push(new ethers.Wallet(k).address);
  }
  PRIVATE_KEYS = valid;
  ALL_WALLETS = addrs;
}

// --- Wallet Persona Management ---
const personaFile = "personas.json";
let walletProfiles = {};
let lastPersonaSave = 0;
const PERSONA_SAVE_DEBOUNCE_MS = 5_000; // coalesce multiple writes into one

async function loadPersonas() {
  try {
    const data = await fs.readFile(personaFile, "utf-8");
    walletProfiles = JSON.parse(data);
    console.log(chalk.cyan("🎭 Loaded existing personas"));
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.log(chalk.yellow("🎭 Personas file not found, starting fresh."));
    } else {
      console.error(chalk.bgRed.white.bold("❌ Error parsing personas.json, starting fresh."));
    }
    walletProfiles = {};
  }
}

// Debounced save to avoid frequent blocking disk writes
async function savePersonas() {
  try {
    const now = Date.now();
    if (now - lastPersonaSave < PERSONA_SAVE_DEBOUNCE_MS) {
      setTimeout(() => {
        try { fs.writeFile(personaFile, JSON.stringify(walletProfiles, null, 2)); lastPersonaSave = Date.now(); }
        catch (e) { console.error("failed saving personas:", e.message); }
      }, PERSONA_SAVE_DEBOUNCE_MS);
      return;
    }
    await fs.writeFile(personaFile, JSON.stringify(walletProfiles, null, 2));
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
      activeHours: [2 + Math.floor(Math.random() * 4), 22 + Math.floor(Math.random() * 3)], // 2-5 to 22-24 UTC
      cooldownAfterFail: 60 + Math.floor(Math.random() * 120), // 1-3 min
      avgWait: 30 + Math.floor(Math.random() * 40), // base wait time 30-70 sec
      retryBias: Math.random() * 0.5, // 0-50% chance to retry
      // dynamic per-wallet nonce retirement
      maxNonce: 520 + Math.floor(Math.random() * 80),
      // failure tracking
      failCount: 0,
      lastFailAt: null
    };
    savePersonas();
  }
  return walletProfiles[wallet.address];
}

// === NEW: Inactive Wallet Management ===
const inactiveFile = "inactive.json";
let inactiveWallets = new Set();

async function loadInactive() {
  try {
    const data = await fs.readFile(inactiveFile, "utf-8");
    inactiveWallets = new Set(JSON.parse(data));
    console.log(chalk.gray(`📂 Loaded ${inactiveWallets.size} inactive wallets`));
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.log(chalk.yellow("📂 Inactive file not found, starting empty."));
    } else {
      console.error("❌ Failed parsing inactive.json, starting empty");
    }
    inactiveWallets = new Set();
  }
}

async function saveInactive() {
  try {
    await fs.writeFile(inactiveFile, JSON.stringify([...inactiveWallets], null, 2));
  } catch (e) {
    console.error("❌ Failed saving inactive.json:", e.message);
  }
}

// --- Dynamic Log File Management (Daily Rotation) ---
// This function returns the log file path for the current day.
function getLogFile() {
  const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD format
  return path.join(__dirname, `tx_log_${today}.csv`);
}

async function initLogFile() {
  const logFile = getLogFile();
  try {
    await fs.access(logFile);
  } catch (e) {
    // File doesn't exist, create it with a header
    await fs.writeFile(
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
async function flushTxLog() {
  if (txBuffer.length === 0) return;
  const logFile = await initLogFile();
  await fs.appendFile(logFile, txBuffer.join("\n") + "\n");
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

// --- Proxy Variables ---
let proxies = [];

// --- Proxy Functions ---
async function loadProxies() {
  try {
    const fileContent = await fs.readFile("proxy.txt", "utf8");
    proxies = fileContent.split("\n").map(proxy => proxy.trim()).filter(proxy => proxy);
    if (proxies.length === 0) {
      console.log(chalk.cyan(`[${new Date().toISOString()}] ⟐ No proxy found in proxy.txt. Running without proxy.`));
    } else {
      console.log(chalk.green(`[${new Date().toISOString()}] ✔ Loaded ${proxies.length} proxies from proxy.txt`));
    }
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.log(chalk.cyan(`[${new Date().toISOString()}] ⟐ No proxy.txt found, running without proxy.`));
    } else {
      console.log(chalk.red(`[${new Date().toISOString()}] ✖ Failed to load proxy: ${error.message}`));
    }
    proxies = [];
  }
}

function createAgent(proxyUrl) {
  if (!proxyUrl) return null;
  if (proxyUrl.startsWith("socks")) {
    return new SocksProxyAgent(proxyUrl);
  } else {
    return new HttpsProxyAgent(proxyUrl);
  }
}

// --- Provider with proxy support ---
function getProvider(rpcUrl, agent) {
  const network = {
    chainId: 42220,
    name: "celo"
  };
  const providerOptions = agent ? { fetchOptions: { agent } } : {};
  return new ethers.JsonRpcProvider(rpcUrl, network, providerOptions);
}

/**
 * Attempts to connect to an RPC endpoint.
 * @returns {Promise<{provider: ethers.JsonRpcProvider, url: string}|null>} The working provider and its URL, or null if all fail.
 */
async function tryProviders() {
  console.log(chalk.hex("#00FFFF").bold("🔍 Searching for a working RPC endpoint..."));
  for (const url of RPCS) {
    try {
      const proxyUrl = proxies.length > 0 ? proxies[Math.floor(Math.random() * proxies.length)] : null;
      const agent = createAgent(proxyUrl);

      const provider = getProvider(url, agent);
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

// === NEW: Active Hours Check ===
function checkActive(wallet, profile) {
  if (isWithinActiveHours(profile)) {
    if (inactiveWallets.has(wallet.address)) {
      inactiveWallets.delete(wallet.address);
      saveInactive();
      console.log(chalk.green(`✅ Wallet ${wallet.address} re-activated`));
    }
    return true;
  } else {
    if (!inactiveWallets.has(wallet.address)) {
      inactiveWallets.add(wallet.address);
      saveInactive();
      console.log(chalk.gray(`🛌 Wallet ${wallet.address} marked inactive`));
    }
    return false;
  }
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

// === NEW: Refresh inactive wallets every 30 minutes ===
setInterval(async () => {
  console.log(chalk.cyan("🔄 Refreshing inactive wallets..."));
  for (const addr of [...inactiveWallets]) {
    const profile = walletProfiles[addr];
    if (profile && isWithinActiveHours(profile)) {
      inactiveWallets.delete(addr);
      console.log(chalk.green(`🌅 Wallet ${addr} is now inside active hours`));
    }
  }
  await saveInactive();
}, 30 * 60 * 1000);

async function main() {
  // Load keys (env primary, file fallback)
  await loadKeysInline({ allowFileFallback: true });

  if (PRIVATE_KEYS.length === 0) {
    console.error(chalk.bgRed.white.bold(`❌ No valid private keys found (env or ${keysFile}). Make sure PRIVATE_KEYS env var or ${keysFile} exists and contains keys.`));
    process.exit(1);
  }


  await loadPersonas();
  await loadInactive();
  await loadProxies();

  // === NEW LOGIC: Initial log file creation before the loop starts ===
  await initLogFile();

  while (true) {
    // === NEW LOGIC: Check if all wallets are inactive and sleep if so ===
    if (inactiveWallets.size >= ALL_WALLETS.length) {
      console.log(chalk.yellow("😴 All wallets are currently inactive. Sleeping for 5 minutes..."));
      await randomDelay(240, 360); // 5 minutes
      continue;
    }

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

    // === NEW: Main loop modification ===
    if (!checkActive(wallet, profile)) {
      await randomDelay(10, 15);
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

main();

// ensure flush/persona save on termination/unhandled
process.on("SIGINT", async () => {
  console.log("SIGINT received, shutting down gracefully...");
  await flushTxLog();
  await savePersonas();
  process.exit();
});
process.on("SIGTERM", async () => {
  console.log("SIGTERM received, shutting down gracefully...");
  await flushTxLog();
  await savePersonas();
  process.exit();
});
process.on("exit", async () => {
  console.log("Exiting, flushing final logs...");
  await flushTxLog();
  await savePersonas();
});
process.on("unhandledRejection", async (r) => {
  console.error("unhandledRejection:", r);
  await flushTxLog();
  await savePersonas();
  process.exit(1);
});
