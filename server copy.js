const express = require("express");
const http = require("http");
const WebSocket = require("ws");

const app = express();

app.get("/", (req, res) => {
  res.send(`
        <h2>UISP Protocol Analyzer</h2>
        <p>Server is running.</p>
        <p>Waiting for WebSocket connections...</p>
    `);
});

const server = http.createServer(app);

// const wss = new WebSocket.Server({
//   server,
// });
const wss = new WebSocket.Server({
  server,
  handleProtocols: (protocols) => {
    console.log("Requested Protocols:", [...protocols]);

    if (protocols.has("unms2")) {
      console.log("Using protocol: unms2");
      return "unms2";
    }

    console.log("No supported protocol.");
    return false;
  },
});
const fs = require("fs");
const path = require("path");
console.log("===========================================");
console.log(" UISP Protocol Analyzer Started");
console.log("===========================================");

let connectionCount = 0;

wss.on("connection", (ws, request) => {
  const startTime = new Date();
  connectionCount++;

  let packetNumber = 0;

  console.log(`Connection #${connectionCount}`);
  console.log("\n===========================================");
  console.log(" NEW CONNECTION");
  console.log("===========================================");

  console.log("Time:", startTime.toISOString());

  console.log("\nRemote Address:");
  console.log(
    request.headers["x-forwarded-for"] || request.socket.remoteAddress,
  );

  console.log("\nHeaders:");

  console.log(request.headers);

  console.log("\nRequested URL:");

  console.log(request.url);

  console.log("\n===========================================");

  // Send something back
  // ws.send("HELLO FROM TEST SERVER");

  ws.on("message", (message, isBinary) => {
    const buffer = Buffer.from(message);
    packetNumber++;

    console.log(`Packet #${packetNumber}`);

    console.log("\n-------------------------------------------");
    console.log("MESSAGE RECEIVED");
    console.log("-------------------------------------------");

    console.log("Timestamp:", new Date().toISOString());

    console.log("Binary:", isBinary);

    console.log("Length:", buffer.length, "bytes");

    console.log("\nHEX:");

    console.log(buffer.toString("hex"));

    // console.log("\nUTF-8:");

    const text = buffer.toString("utf8");

    console.log("\nUTF8:");
    console.log(text);

    const looksLikeBase64Url = /^[A-Za-z0-9\-_]+$/.test(text);

    console.log("\nLooks Like Base64URL:", looksLikeBase64Url);
    console.log(buffer.toString("utf8"));

    console.log("-------------------------------------------");
  });

  ws.on("close", (code, reason) => {
    console.log("\n===========================================");
    console.log(" CONNECTION CLOSED");
    console.log("===========================================");

    console.log("Time:", new Date().toISOString());

    console.log("Duration:", (new Date() - startTime) / 1000, "seconds");

    console.log("Close Code:", code);

    console.log("Reason:", reason.toString());

    console.log("===========================================\n");
  });

  ws.on("error", (err) => {
    console.log("\n###########################################");
    console.log(" WEBSOCKET ERROR");
    console.log("###########################################");

    console.error(err);

    console.log("###########################################\n");
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`HTTP Server running on port ${PORT}`);
});
