const express = require("express");
const http = require("http");
const crypto = require('crypto');
const WebSocket = require("ws");
const fs = require("fs");
const path = require("path");
const ssh_Client = require('ssh2').Client;

const app = express();

console.log("Script Running!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
function parseUnmsUrl(url) {
  const withoutScheme = url.replace(/^wss?:\/\//, '');
  const parts = withoutScheme.split('+');
  const hostPort = parts[0];
  const connectionKey = parts[1];      // 48-char base64url string
  const flags = parts.slice(2);
  const [host, port] = hostPort.split(':');
  return { host, port: Number(port), connectionKey, flags };
}


function connectSSH(config) {
  return new Promise((resolve, reject) => {
    const conn = new ssh_Client();

    conn.on('ready', () => {
      resolve(conn);
    });

    conn.on('error', (err) => {
      reject(err);
    });

    conn.connect({
      host: config.host,
      port: config.port || 22,
      username: config.username,
      password: config.password,
      // Force the client to accept legacy ssh-rsa host key algorithms
      algorithms: {
        serverHostKey: [
          'ssh-rsa',
          'ssh-dss'
        ]
      },
      // Optional: Skip strict host key checking if you do not have the known_hosts file
      readyTimeout: 20000
    });
  });
}


function b64urlToBuffer(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// Confirmed by decode_unms_key: 48-char base64url -> 36 raw bytes, first 32 used as key.
function deriveKey(connectionKey) {
  if (connectionKey.length !== 48) {
    throw new Error(`expected 48-char connection key, got ${connectionKey.length}`);
  }
  const decoded = b64urlToBuffer(connectionKey); // 36 bytes
  return decoded.subarray(0, 32);                // 32-byte AES-256 key
}

// Confirmed by unms_decode: part0[0:22]=IV(16B), part1[22:44]=tag(16B), part2[44:]=ciphertext
function splitMessage(raw) {
  return {
    iv:         b64urlToBuffer(raw.slice(0, 22)),   // 16 bytes, confirmed via EVP_CTRL_GCM_SET_IVLEN=16
    tag:        b64urlToBuffer(raw.slice(22, 44)),  // 16 bytes
    ciphertext: b64urlToBuffer(raw.slice(44)),
  };
}

function decryptUnmsMessage(url, rawMessage) {
  const { connectionKey } = parseUnmsUrl(url);
  const key = deriveKey(connectionKey);
  const { iv, tag, ciphertext } = splitMessage(rawMessage);
  console.log('key (hex):', key.toString('hex'), 'len:', key.length);
  console.log('iv (hex):', iv.toString('hex'), 'len:', iv.length);
  console.log('tag (hex):', tag.toString('hex'), 'len:', tag.length);
  console.log('ciphertext len:', ciphertext.length);
  console.log('raw message length:', rawMessage.length);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv); // 16-byte IV, confirmed correct
  
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return JSON.parse(plaintext.toString('utf8'));
}



const url = 'wss://uisp-protocol-analyzer-62854-05151d8622e2.herokuapp.com:443+9kT9fOBtILrr0UPdQu4WuQ7z59vPGuPRrerBvvzJk9ucSbhO+allowUntrustedCertificate';
// const rawMessage = '354b4f53553056424b61376670454b667170414c42677979433341584d75525a5f4832416b6a426b67317377394f4c476c434f4d677773793837324a4941644f547a467742534546636c7259424658324a39684963324f3359615352454572717a46732d666550575a75682d66627432356d39385572544c41785674734e796952733276716237706b４N５２７３４５０６ｆ０６２７１４６ｅ４Ｎ５４２ｄ４６３８５５７２７７５７６４';


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


let connectionCounter = 0;
wss.on("connection", (ws, request) => {
  rawAddress = request.socket.remoteAddress;
  remoteAddress = request.headers["x-forwarded-for"]
  async function run() {
    
  const credentials = {
    host: remoteAddress,
    username: 'ubnt',
    password: 'testing1234567'
  };
  try {
    console.log('Connecting...');
    const conn = await connectSSH(credentials);
    console.log('SSH Connection Successful!');
    
    // Execute a simple command
    conn.exec('uptime', (err, stream) => {
      if (err) throw err;
      stream.on('close', (code, signal) => {
        conn.end();
      }).on('data', (data) => {
        console.log('STDOUT: ' + data);
      }).stderr.on('data', (data) => {
        console.log('STDERR: ' + data);
      });
    });

  } catch (error) {
    console.error('Connection failed:', error.message);
  }
  }
  run();

  connectionCounter++;

  const connectionId = connectionCounter;

  const startTime = Date.now();

  let packetCounter = 0;

  console.log("\n");
  console.log("##################################################");
  console.log(`CONNECTION #${connectionId}`);
  console.log("##################################################");
  console.log("Raw Address:");
  console.log(rawAddress);
  

  console.log("\nRemote Address:");

  console.log(remoteAddress);
  

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
    console.log("new message recieved!!!!!!!!!!!!!!!!!!!!!!!!!")
    // packetCounter++;

    // const buffer = Buffer.from(message);
    // const url = 'wss://Invisec.uisp.com:443+9kT9fOBtILrr0UPdQu4WuQ7z59vPGuPRrerBvvzJk9ucSbhO+allowUntrustedCertificate';

    // decryptedMessage = decryptUnmsMessage(url, buffer.toString());

    // console.log("\n-------------------------------------------");
    // console.log("MESSAGE RECEIVED");
    // console.log("-------------------------------------------");

    // console.log("Timestamp:", new Date().toISOString());

    // console.log("Binary:", isBinary);

    // console.log("Length:", decryptedMessage.length, "bytes");

    // console.log("\nHEX:");

    // console.log(decryptedMessage.toString("hex"));

    // console.log("\nUTF-8:");

    // console.log(decryptedMessage.toString("utf8"));
    
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
