const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const fs = require("fs");
const path = require("path");

const app = express();

app.get("/", (req, res) => {
  res.send(`
        <h2>UISP Protocol Analyzer</h2>
        <p>Server is running.</p>
        <p>Waiting for AirMAX devices...</p>
    `);
});

const server = http.createServer(app);

const CAPTURE_DIR = path.join(__dirname, "captures");

if (!fs.existsSync(CAPTURE_DIR)) {
  fs.mkdirSync(CAPTURE_DIR);
}

server.on("upgrade", (request, socket, head) => {
  console.log("\n==================================================");
  console.log("HTTP UPGRADE REQUEST");
  console.log("==================================================");

  console.log("Time:", new Date().toISOString());
  console.log("URL:", request.url);

  console.log("\nHeaders:");
  console.log(request.headers);

  console.log("==================================================");
});

const wss = new WebSocket.Server({
  server,

  handleProtocols: (protocols) => {
    console.log("\nRequested WebSocket Protocols:");

    console.log([...protocols]);

    if (protocols.has("unms2")) {
      console.log("Accepting protocol: unms2");

      return "unms2";
    }

    console.log("No supported protocol requested.");

    return false;
  },
});

console.log("==================================================");
console.log(" UISP Protocol Analyzer Started");
console.log("==================================================");

let connectionCounter = 0;

wss.on("connection", (ws, request) => {
  connectionCounter++;

  const connectionId = connectionCounter;

  const startTime = Date.now();

  let packetCounter = 0;

  console.log("\n");
  console.log("##################################################");
  console.log(`CONNECTION #${connectionId}`);
  console.log("##################################################");

  console.log("Time:", new Date().toISOString());

  console.log("\nRemote Address:");

  console.log(
    request.headers["x-forwarded-for"] || request.socket.remoteAddress,
  );

  console.log("\nHeaders:");

  console.log(request.headers);
  console.log("===========================================");

  console.log("\nRequested URL:");
  console.log(request.url);

  const metadata = {
    connectionId,
    time: new Date().toISOString(),
    ip: request.headers["x-forwarded-for"] || request.socket.remoteAddress,
    headers: request.headers,
  };

  fs.writeFileSync(
    path.join(CAPTURE_DIR, `connection_${connectionId}.json`),
    JSON.stringify(metadata, null, 2),
  );

  // IMPORTANT:
  // DO NOT SEND ANYTHING.
  // We want the device to speak first.

  ws.on("message", (message, isBinary) => {
    packetCounter++;

    const buffer = Buffer.from(message);

    const text = buffer.toString("utf8");

    const timestamp = Date.now();

    const looksLikeBase64URL = /^[A-Za-z0-9\-_]+$/.test(text);

    console.log("\n--------------------------------------------------");
    console.log(`CONNECTION ${connectionId} | PACKET ${packetCounter}`);
    console.log("--------------------------------------------------");

    console.log("Timestamp:", new Date().toISOString());

    console.log("Binary:", isBinary);

    console.log("Length:", buffer.length, "bytes");

    console.log("Looks Like Base64URL:", looksLikeBase64URL);

    console.log("\nHEX:");

    console.log(buffer.toString("hex"));

    console.log("\nUTF-8:");

    console.log(text);

    console.log("--------------------------------------------------");

    fs.writeFileSync(
      path.join(CAPTURE_DIR, `conn${connectionId}_packet${packetCounter}.bin`),
      buffer,
    );

    fs.writeFileSync(
      path.join(CAPTURE_DIR, `conn${connectionId}_packet${packetCounter}.hex`),
      buffer.toString("hex"),
    );

    fs.writeFileSync(
      path.join(CAPTURE_DIR, `conn${connectionId}_packet${packetCounter}.txt`),
      text,
    );
  });

  ws.on("ping", () => {
    console.log(`PING received from connection ${connectionId}`);
  });

  ws.on("pong", () => {
    console.log(`PONG received from connection ${connectionId}`);
  });

  ws.on("close", (code, reason) => {
    console.log("\n==================================================");
    console.log(`CONNECTION ${connectionId} CLOSED`);
    console.log("==================================================");

    console.log("Time:", new Date().toISOString());

    console.log(
      "Duration:",
      ((Date.now() - startTime) / 1000).toFixed(3),
      "seconds",
    );

    console.log("Packets Received:", packetCounter);

    console.log("Close Code:", code);

    console.log("Reason:", reason.toString());

    console.log("==================================================");
  });

  ws.on("error", (err) => {
    console.log("\n##################################################");
    console.log(`WEBSOCKET ERROR (Connection ${connectionId})`);
    console.log("##################################################");

    console.error(err);

    console.log("##################################################");
  });
});

const PORT = process.env.PORT || 443;

server.listen(PORT, () => {
  console.log(`HTTP Server running on port ${PORT}`);
});
