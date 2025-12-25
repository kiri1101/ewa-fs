import express from "express";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// ENV & BASIC SETUP //
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
const ASSETS_ROOT = path.resolve(process.env.ASSETS_ROOT || "assets");

// SECURITY MIDDLEWARE //
app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);

// CORS CONFIGURATION //
// Allowed origins (comma-separated) e.g. http://localhost:3000,https://app.example.com //
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map(o => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, x-client-id, x-client-secret"
    );
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json());

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
  })
);

function loadClients() {
  const clients = {};
  const list = (process.env.CLIENTS || "")
    .split(",")
    .map(c => c.trim())
    .filter(Boolean);

  for (const name of list) {
    const id = process.env[`${name.toUpperCase()}_ID`];
    const secret = process.env[`${name.toUpperCase()}_SECRET`];

    if (!id || !secret) {
      throw new Error(`Missing credentials for client ${name}`);
    }

    clients[id] = {
      name,
      secret,
      assetDir: path.join(ASSETS_ROOT, name),
    };
  }

  return clients;
}

const CLIENTS = loadClients();

// AUTH MIDDLEWARE //
function authenticateClient(req, res, next) {
  const clientId = req.header("x-client-id");
  const clientSecret = req.header("x-client-secret");

  if (!clientId || !clientSecret) {
    return res.status(401).json({ error: "Missing authentication headers" });
  }

  const client = CLIENTS[clientId];

  if (!client || client.secret !== clientSecret) {
    return res.status(403).json({ error: "Invalid client credentials" });
  }

  req.client = client;
  next();
}

// ASSET LISTING HELPER //
function buildAssetIndex(req, clientName, dirPath) {
  const result = {};

  const walk = currentDir => {
    for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        walk(fullPath);
      } else {
        const relativeKey = path
          .relative(dirPath, fullPath)
          .replace(/\\/g, "/")
          .replace(/\.[^/.]+$/, "");

        const baseUrl = `${req.protocol}://${req.get("host")}`;
        result[relativeKey] = `${baseUrl}/assets/${clientName}/${path
          .relative(dirPath, fullPath)
          .replace(/\\/g, "/")}`;
      }
    }
  };

  walk(dirPath);
  return result;
}

// ROUTES //
app.get("/api/assets", authenticateClient, (req, res) => {
  const { name, assetDir } = req.client;

  if (!fs.existsSync(assetDir)) {
    return res.json({});
  }

  const assets = buildAssetIndex(req, name, assetDir);
  res.json(assets);
});

// Static serving (isolated per client) //
app.use("/assets/:client", (req, res, next) => {
  const client = Object.values(CLIENTS).find(c => c.name === req.params.client);
  if (!client) return res.sendStatus(404);
  express.static(client.assetDir)(req, res, next);
});

// HEALTH CHECK //
app.get("/health", (_, res) => res.send("OK"));

// START //
app.listen(PORT, () => {
  console.log(`Asset server running on port ${PORT}`);
});
