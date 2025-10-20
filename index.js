import { ethers, FetchRequest } from "ethers";
import dotenv from "dotenv";
import * as fs from "fs/promises";
import path from "path";
import chalk from "chalk";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
import { fileURLToPath } from "url";
import crypto from "crypto";

dotenv.config();

// Define __dirname equivalent for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const LOG_DIR = __dirname;


// ==========================
// ✅ Resource & Error Safety
// ==========================

/**
 * Tracks and logs memory usage at regular intervals.
 */
setInterval(() => {
    const used = process.memoryUsage();
    const rssMB = (used.rss / 1024 / 1024).toFixed(1);
    const heapMB = (used.heapUsed / 1024 / 1024).toFixed(1);
    console.log(chalk.cyan(`[Monitor] RSS: ${rssMB} MB | Heap: ${heapMB} MB`));
}, 10 * 60 * 1000);

/**
 * Handles graceful shutdown by flushing logs and saving state.
 * @param {number} code - The exit code.
 */
async function safeExit(code = 0) {
    console.log(chalk.yellow.bold("[Exit] Flushing logs & saving state..."));
    try {
        await flushTxLog();
        await savePersonas();
        await saveInactive();
    } catch (err) {
        console.error(chalk.red.bold("[Exit Error]"), err.message);
    }
    process.exit(code);
}

process.on("SIGINT", () => {
    console.log(chalk.yellow.bold("\n[Signal] Caught SIGINT (Ctrl+C)."));
    safeExit(0);
});
process.on("SIGTERM", () => {
    console.log(chalk.yellow.bold("\n[Signal] Caught SIGTERM."));
    safeExit(0);
});

// Catch uncaught errors without crashing
process.on("uncaughtException", (err) => {
    console.error(chalk.bgRed.white.bold("[Uncaught Exception]"), err);
});
process.on("unhandledRejection", (reason, promise) => {
    console.error(chalk.bgRed.white.bold("[Unhandled Rejection]"), reason);
});

// === NEW: In-Memory Encryption Helper Functions ===
const ALGO = "aes-256-gcm";
const IV_LENGTH = 12;

// --- Master Keys ---
const MASTER_KEY = process.env.MASTER_KEY;
const BACKUP_KEYS = (process.env.BACKUP_KEYS || "")
    .split(",")
    .map(k => k.trim())
    .filter(Boolean);

if (!MASTER_KEY) {
    console.error(chalk.bgRed.white.bold("❌ MASTER_KEY environment variable is not set!"));
    process.exit(1);
}

const ALL_MASTER_KEYS = [MASTER_KEY, ...BACKUP_KEYS];

// --- Session Salt for Stronger Key Derivation ---
let sessionSalt = crypto.randomBytes(16);

// Rotate session salt hourly
setInterval(() => {
    sessionSalt = crypto.randomBytes(16);
    console.log(chalk.cyan("🔑 Rotated session salt for key derivation"));
}, 60 * 60 * 1000);

/**
 * Derives a cryptographic key from a master key and a session salt.
 * @param {string} masterKey - The master key for key derivation.
 * @returns {Buffer} The derived key as a Buffer.
 */
function deriveKey(masterKey) {
    return crypto.scryptSync(masterKey, sessionSalt, 32);
}

/**
 * Encrypts a private key using a master key.
 * @param {string} privateKey - The private key to encrypt.
 * @param {string} masterKey - The master key for encryption.
 * @returns {string} The encrypted key string in the format "iv:authTag:encrypted".
 */
function encryptPrivateKey(privateKey, masterKey) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const derivedKey = deriveKey(masterKey);
    const cipher = crypto.createCipheriv(ALGO, derivedKey, iv);

    let encrypted = cipher.update(privateKey, "utf8", "hex");
    encrypted += cipher.final("hex");

    const authTag = cipher.getAuthTag().toString("hex");
    return `${iv.toString("hex")}:${authTag}:${encrypted}`;
}

/**
 * Decrypts an encrypted private key.
 * @param {string} encrypted - The encrypted key string.
 * @param {string} masterKey - The master key for decryption.
 * @returns {string} The decrypted private key.
 */
function decryptPrivateKey(encrypted, masterKey) {
    const [ivHex, authTagHex, data] = encrypted.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const derivedKey = deriveKey(masterKey);
    const decipher = crypto.createDecipheriv(ALGO, derivedKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(data, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

/**
 * Attempts to decrypt an encrypted key with any of the available master keys.
 * This provides resilience if a new master key is rolled out.
 * @param {string} encrypted - The encrypted key string.
 * @returns {string} The decrypted private key.
 * @throws {Error} If decryption fails with all keys.
 */
function decryptWithAnyKey(encrypted) {
    for (const key of ALL_MASTER_KEYS) {
        try {
            return decryptPrivateKey(encrypted, key);
        } catch {
            continue;
        }
    }
    throw new Error("❌ Failed to decrypt private key with all available master keys");
}

// === CONFIG ===
// List of public RPCs for Celo.
const RPCS = [
    "https://celo-mainnet.infura.io/v3/f0c6b3797dd54dc2aa91cd4a463bcc57",
    "https://rpc.ankr.com/celo",
    "https://celo.drpc.org",
    "https://forno.celo.org",
    "https://1rpc.io/celo"
];
const GAS_LIMIT = 21000;
const keysFile = "key.txt";
let lastKey = null;

// --- Key loader (env only, one key per line inside PRIVATE_KEYS) ---
// Now stores encrypted keys
let ENCRYPTED_KEYS = [];
let ALL_WALLETS = [];

/**
 * Normalizes a private key string, ensuring it's 0x-prefixed.
 * @param {string} k - The key string to normalize.
 * @returns {string|null} The normalized key or null if invalid.
 */
function normalizeKey(k) {
    if (!k) return null;
    k = String(k).trim();
    if (!k) return null;
    return k.startsWith("0x") ? k : "0x" + k;
}

/**
 * Validates a private key by attempting to construct an ethers.Wallet.
 * @param {string} k - The key to validate.
 * @returns {boolean} True if the key is valid, false otherwise.
 */
function isValidPrivateKey(k) {
    try {
        new ethers.Wallet(k);
        return true;
    } catch {
        return false;
    }
}

/**
 * Loads and encrypts private keys from the PRIVATE_KEYS environment variable.
 */
async function loadKeysInline() {
    const envKeys = process.env.PRIVATE_KEYS || "";
    
    // split by newlines, trim, filter empties
    const keys = envKeys
        .split(/\r?\n/) 
        .map(normalizeKey)
        .filter(Boolean);

    const validKeys = keys.filter(isValidPrivateKey);

    if (validKeys.length === 0) {
        console.error(chalk.bgRed.white.bold("❌ No valid private keys found in PRIVATE_KEYS (env). Each key should be on its own line."));
        process.exit(1);
    }

    // Encrypt keys and store them
    ENCRYPTED_KEYS = validKeys.map(k => encryptPrivateKey(k, MASTER_KEY));
    // Create ALL_WALLETS list using decrypted keys just once at startup
    ALL_WALLETS = validKeys.map(k => new ethers.Wallet(k).address);

    console.log(chalk.cyan(`🔐 Loaded ${ALL_WALLETS.length} wallets (encrypted in memory)`));
}

// === NEW: Device Agent Generation ===
/**
 * Generates a random device agent profile to simulate human-like network traffic.
 * @returns {{userAgent: string, latency: number}} An object containing a user agent string and a simulated network latency in ms.
 */
function generateDeviceAgent() {
    const browsers = ["Chrome", "Firefox", "Edge", "Safari"];
    const os = ["Windows NT 10.0", "Macintosh; Intel Mac OS X 13_0", "Linux x86_64"];

    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    const system = os[Math.floor(Math.random() * os.length)];
    const version = `${Math.floor(Math.random() * 100)}.0.${Math.floor(Math.random() * 1000)}`;

    // Simulated network latency per wallet (in ms)
    const latency = 50 + Math.floor(Math.random() * 200); // 50ms to 250ms

    return {
        userAgent: `${browser}/${version} (${system})`,
        latency
    };
}


// --- Wallet Persona Management ---
const personaFile = "personas.json";
let walletProfiles = {};
let lastPersonaSave = 0;
const PERSONA_SAVE_DEBOUNCE_MS = 5_000; // coalesce multiple writes into one

/**
 * Loads wallet personas from a JSON file.
 */
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

/**
 * Ensures a wallet has a persona profile, creating a new one if it doesn't exist.
 * @param {ethers.Wallet} wallet - The wallet instance.
 * @returns {object} The wallet's persona profile.
 */
function ensurePersona(wallet) {
    if (!walletProfiles[wallet.address]) {
        const deviceAgent = generateDeviceAgent();
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
            lastFailAt: null,
            deviceAgent // store User-Agent + latency
        };
        savePersonas();
    }
    return walletProfiles[wallet.address];
}

// === NEW: Inactive Wallet Management ===
const inactiveFile = "inactive.json";
let inactiveWallets = new Set();

/**
 * Loads the list of inactive wallets from a file.
 */
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

/**
 * Saves the list of inactive wallets to a file.
 */
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

/**
 * Initializes the log file for the current day, adding a header if it doesn't exist.
 * @returns {Promise<string>} The path to the log file.
 */
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

/**
 * Buffers a transaction log entry.
 * @param {string} entry - The log entry string.
 */
function bufferTxLog(entry) {
    txBuffer.push(entry);
}

/**
 * Flushes the transaction log buffer to the daily log file.
 */
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
// Now decrypts the key before use
function pickRandomKey() {
    const idx = Math.floor(Math.random() * ENCRYPTED_KEYS.length);
    const encrypted = ENCRYPTED_KEYS[idx];
    const privateKey = decryptWithAnyKey(encrypted);
    return privateKey;
}

// --- Proxy Variables ---
let proxies = [];

// --- Proxy Functions ---
/**
 * Loads proxies from `proxy.txt`.
 */
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
            console.error(chalk.red(`[${new Date().toISOString()}] ✖ Failed to load proxy: ${error.message}`));
        }
        proxies = [];
    }
}

// Auto-refresh proxies every 15 minutes
setInterval(async () => {
    try {
        const fileContent = await fs.readFile("proxy.txt", "utf8");
        const fresh = fileContent
            .split("\n")
            .map(p => p.trim())
            .filter(p => p.length > 0);

        if (fresh.length > 0) {
            // Only update and log if the proxy list has actually changed
            if (JSON.stringify(proxies) !== JSON.stringify(fresh)) {
                proxies = fresh;
                console.log(chalk.green(`[Proxy] Reloaded ${proxies.length} proxies from file ✅`));
            }
        } else {
            console.warn(chalk.yellow("[Proxy] proxy.txt is empty, keeping old list."));
        }
    } catch (err) {
        // Silently ignore if file doesn't exist, log other errors
        if (err.code !== 'ENOENT') {
            console.error(chalk.red("[Proxy Refresh Error]"), err.message);
        }
    }
}, 15 * 60 * 1000);


function createAgent(proxyUrl) {
    if (!proxyUrl) return null;
    if (proxyUrl.startsWith("socks")) {
        return new SocksProxyAgent(proxyUrl);
    } else {
        return new HttpsProxyAgent(proxyUrl);
    }
}

// --- Provider with proxy and User-Agent support ---
function getProvider(rpcUrl, agent, userAgent) {
    const network = {
        chainId: 42220,
        name: "celo"
    };
    const req = new FetchRequest(rpcUrl);
    if (userAgent) {
        req.setHeader("User-Agent", userAgent);
    }
    if (agent) {
        req.agent = agent;
    }
    return new ethers.JsonRpcProvider(req, network);
}

/**
 * Attempts to connect to an RPC endpoint.
 * @returns {Promise<{provider: ethers.JsonRpcProvider, url: string}|null>} The working provider and its URL, or null if all fail.
 */
async function tryProviders(profile) {
    console.log(chalk.hex("#00FFFF").bold("🔍 Searching for a working RPC endpoint..."));
    for (const url of RPCS) {
        try {
            const proxyUrl = proxies.length > 0 ? proxies[Math.floor(Math.random() * proxies.length)] : null;
            const agent = createAgent(proxyUrl);
            const userAgent = profile.deviceAgent.userAgent;

            const provider = getProvider(url, agent, userAgent);
            const network = await Promise.race([
                provider.getNetwork(),
                new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000))
            ]);
            console.log(chalk.hex("#00FF7F").bold(`✅ Connected: ${url}, Chain ID: ${network.chainId}`));
            return { provider, url };
        } catch (e) {
            console.warn(chalk.hex("#FF5555").bold(`❌ Failed to connect to ${url}: ${e.message}`));
        }
    }
    return null;
}

/**
 * Iterates through the list of RPCs and returns the first one that successfully connects.
 * @returns {Promise<{provider: ethers.JsonRpcProvider, url: string}>} The working provider and its URL.
 */
async function getWorkingProvider(profile) {
    return await tryProviders(profile);
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

/**
 * Sends a transaction from a wallet to itself.
 * @param {ethers.Wallet} wallet - The wallet instance.
 * @param {ethers.JsonRpcProvider} provider - The RPC provider.
 * @param {object} profile - The wallet's persona profile.
 * @param {string} url - The URL of the RPC being used.
 * @throws {Error} If the transaction fails.
 */
async function sendTx(wallet, provider, profile, url) {
    try {
        if (Math.random() < profile.idleBias) {
            console.log(chalk.hex("#808080").italic("\n😴 Persona idle mode, skipping this cycle..."));
            return;
        }

        // === NEW: Simulate Network Latency ===
        console.log(chalk.hex("#FFA500").bold(`🌐 Simulating network latency: ${profile.deviceAgent.latency}ms...`));
        await new Promise(res => setTimeout(res, profile.deviceAgent.latency));

        const balance = await provider.getBalance(wallet.address);
        await randomDelay(2, 4);

        const walletNonce = await provider.getTransactionCount(wallet.address);
        await randomDelay(2, 4); // Another short delay

        const maxNonce = profile.maxNonce;
        if (walletNonce >= maxNonce) {
            console.warn(chalk.bgYellow.black.bold(`\n🟡 Wallet: ${wallet.address} nonce ${walletNonce} >= ${maxNonce}. Skipping.`));
            return;
        }

        console.log(chalk.hex("#1E90FF").bold.underline(`\n🎲 Wallet: ${wallet.address}`));
        console.log(chalk.hex("#1E90FF").bold(`Using RPC: ${url}`));
        console.log(chalk.hex("#FFD700").bold(`Balance: ${ethers.formatEther(balance)} CELO`));
        console.log(chalk.hex("#FFD700").bold(`Nonce: ${walletNonce}`));

        if (balance < ethers.parseEther("0.01")) {
            console.warn(chalk.hex("#FFA500").bold("⚠️ Not enough balance, skipping..."));
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

        // Determine recipient address
        let toAddress = wallet.address;
        let pingType = "self";
        if (action === "ping") {
            const rand = Math.random();
            if (rand < 0.5) {
                toAddress = wallet.address; // self
                pingType = "self";
            } else if (rand < 0.7) {
                toAddress = "0x0000000000000000000000000000000000000000"; // dead address
                pingType = "dead";
            } else {
                const randomWallet = ethers.Wallet.createRandom();
                toAddress = randomWallet.address; // random generated
                pingType = "random";
            }
        }

        const tx = await wallet.sendTransaction({
            to: toAddress,
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
                console.warn(chalk.bgYellow.white.bold("🟡 No confirmation in 30s, moving on..."));
                status = "timeout";
            }
        } catch (err) {
            console.error(chalk.bgRed.white.bold("❌ Error fetching receipt:", err.message));
            status = "error";
        }

        // === Buffer to CSV (daily rotation) ===
        const detailedAction = action === "ping" ? `${action}_${pingType}` : action;
        const line = [
            new Date().toISOString(),
            wallet.address,
            tx.hash,
            txNonce,
            gasUsed,
            gasPriceGwei,
            feeCELO,
            status,
            detailedAction
        ].join(",");
        bufferTxLog(line);

    } catch (err) {
        console.error(chalk.bgRed.white.bold("❌ Error in sendTx:", err.message));
        throw err; // Re-throw to be caught by safeSendTx for cooldown logic
    }
}

/**
 * Safely sends a transaction, including retry and cooldown logic.
 * @param {ethers.Wallet} wallet - The wallet instance.
 * @param {ethers.JsonRpcProvider} provider - The RPC provider.
 * @param {object} profile - The wallet's persona profile.
 * @param {string} url - The URL of the RPC being used.
 */
async function safeSendTx(wallet, provider, profile, url) {
    try {
        await sendTx(wallet, provider, profile, url);
    } catch (err) {
        console.warn(chalk.hex("#FFA500").bold("⚠️ Transaction failed. Checking persona retry bias..."));

        // NEW LOGIC: Check retry bias and apply cooldown
        if (Math.random() > profile.retryBias) {
            console.warn(chalk.hex("#FF8C00")(`⏸ Persona ${wallet.address} cooling down after fail...`));
            // Add a small jitter to the cooldown period
            const cooldownSec = profile.cooldownAfterFail + Math.floor(Math.random() * 60);
            await randomDelay(cooldownSec, cooldownSec);
            return;
        }

        console.warn(chalk.hex("#FFA500").bold("⚠️ Retrying after error..."));
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

/**
 * Deletes log files older than 3 days.
 */
async function cleanupOldLogs() {
    console.log(chalk.cyan("🗑️ Running scheduled log cleanup..."));
    try {
        const files = await fs.readdir(LOG_DIR);
        const cutoff = Date.now() - (3 * 24 * 60 * 60 * 1000); // 3 days
        for (const file of files) {
            const filePath = path.join(LOG_DIR, file);
            // Skip directories and non-log files
            const stats = await fs.stat(filePath);
            if (!stats.isFile() || !file.startsWith("tx_log_") || !file.endsWith(".csv")) {
                continue;
            }
            
            if (stats.mtimeMs < cutoff) {
                await fs.unlink(filePath);
                console.log(chalk.gray(`[Logs] Deleted old log: ${file}`));
            }
        }
        console.log(chalk.green('✅ Log cleanup complete.'));
    } catch (err) {
        console.error(chalk.bgRed.white.bold('[Logs] Cleanup error:'), err.message);
    }
}

async function main() {
    // Check for a `--clear-logs` flag on startup
    if (process.argv.includes('--clear-logs')) {
        console.log(chalk.yellow.bold(`🗑️ --clear-logs flag detected. Deleting all old log files...`));
        try {
            const files = await fs.readdir(__dirname);
            const logFiles = files.filter(file => /^tx_log_\d{4}-\d{2}-\d{2}\.csv$/.test(file));
            for (const file of logFiles) {
                await fs.unlink(path.join(__dirname, file));
                console.log(chalk.gray(`   - Deleted ${file}`));
            }
            console.log(chalk.green('✅ Old logs cleared successfully.'));
        } catch (err) {
            console.error(chalk.bgRed.white.bold('❌ Error while clearing old logs:'), err.message);
        }
    }

    // Load keys (env primary, file fallback)
    await loadKeysInline();

    await loadPersonas();
    await loadInactive();
    await loadProxies();

    // === Initial log file creation and cleanup ===
    await initLogFile();
    await cleanupOldLogs();

    while (true) {
        // Pick a wallet and its persona
        let key = pickRandomKey();
        let wallet = new ethers.Wallet(key);
        const profile = ensurePersona(wallet);

        // === NEW LOGIC: Check if all wallets are inactive and sleep if so ===
        if (inactiveWallets.size >= ALL_WALLETS.length) {
            console.warn(chalk.yellow("😴 All wallets are currently inactive. Sleeping for 5 minutes..."));
            await randomDelay(240, 360); // 5 minutes
            continue;
        }

        // === NEW LOGIC: Retry loop for RPC connection ===
        let provider = null;
        let url = null;
        while (!provider) {
            const providerResult = await getWorkingProvider(profile);
            if (providerResult) {
                provider = providerResult.provider;
                url = providerResult.url;
            } else {
                console.warn(chalk.hex("#FF8C00").bold("🚫 All RPCs failed to connect. Retrying in 10 seconds..."));
                await randomDelay(10, 15);
            }
        }
        // === END NEW LOGIC ===

        // Re-attach wallet to the working provider
        wallet = new ethers.Wallet(key, provider);

        // === NEW: Main loop modification ===
        if (!checkActive(wallet, profile)) {
            await randomDelay(10, 15);
            continue;
        }

        // Execute the transaction logic, including retries
        await safeSendTx(wallet, provider, profile, url);

        // Explicit memory wipe after use
        key = null;
        wallet = null;

        // NEW LOGIC: Use persona's avgWait for the wait loop
        let waitSec = Math.floor(profile.avgWait * (0.8 + Math.random() * 0.4));

        console.log(chalk.hex("#00CED1").italic.bold(`⏳ Waiting ${waitSec}s before next tx...`));
        await randomDelay(waitSec, waitSec);
    }
}

main();
