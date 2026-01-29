const crypto = require("node:crypto");
const dgram = require("node:dgram");
const { normalizeAddressDetailed, decodeAddress } = require("./net-utils.js");
const { sleep } = require("./utils.js");
const { blake3 } = require('@noble/hashes/blake3.js');
const { ACTIVE_CONN, HEADER_SIZE, MAX_PACKET, PASSIVE_CONN, PROTOCOl_VERSION, NETWORK_MAGIC, CONNECTION_STATES } = require("./constants.js");
const { decodeMessage, encodeMessage, MSG_CONNECT, MSG_PING, MSG_PONG } = require("./messages.js");
const { newConnection } = require("./connectManager.js");
const { encodeConnectionFlags, encodeConnection, processConnect } = require("./messages/connect.js");
const { encodePing, processPing, pingActive, pingPassive } = require("./messages/ping.js");

class Client {
  constructor(getTcpInfo, udpAddr, udpPort) {
    this.connections = new Map();

    this.getTcpInfo = getTcpInfo;
    this.udpAddr = udpAddr;
    this.udpPort = udpPort;

    this.udpServer = dgram.createSocket({ type: 'udp6' });
    this.udpServer.bind(udpPort, udpAddr);

    setInterval(() => {
      this.pingActive();

      setTimeout(() => {
        this.pingPassive();
      }, 500);
    }, 1000);

    this.udpServer.on("message", (buf, sender) => {
      try {
        if (buf.length < HEADER_SIZE) return;
        if (buf.length > MAX_PACKET) return;

        const msg = decodeMessage(buf);
        const connInfo = normalizeAddressDetailed(sender.address, sender.port);

        if (msg.signature) {
          const connObj = this.connections.get(connInfo.string);
          
          if (!connObj || !connObj.sharedSecret) throw Error("Invalid Signature");
          const expectedSignature = Buffer.from(
            blake3.create({ key: Buffer.from(connObj.sharedSecret) })
            .update(buf.subarray(0, HEADER_SIZE))
            .update(msg.payload)
            .digest()
          );

          if (!crypto.timingSafeEqual(msg.signature, expectedSignature)) throw Error("Invalid Signature");

          connObj.lastSeen = Date.now();

          this.processMessage(connObj, connInfo, msg);
        } else if (msg.header.msgType === MSG_CONNECT) {
          this.processConnect(connInfo, msg);
        }
      } catch(e) {
        console.log(e)
      }
    });
  }

  send(buf, port, address) {
    return new Promise((resolve) => {
      this.udpServer.send(buf, port, address, () => {
        resolve();
      })
    })
  }

  didReceiveConn(connStr) {
    const existing = this.connections.get(connStr);
    if (!existing) return false;

    return existing.connState != CONNECTION_STATES.CONNECTING;
  }

  async connect(rawAddr, externalPort) {
    const { address: externalAddr, string: connStr } = normalizeAddressDetailed(rawAddr, externalPort);

    const existing = this.connections.get(connStr);

    if (existing) {
      if (existing.type === ACTIVE_CONN) return;
      if (existing.connState != CONNECTION_STATES.CONNECTED) return;

      console.log("Promoting", connStr, existing);

      if ((Date.now() - existing.lastSeen) <= 10000) {
        existing.type = ACTIVE_CONN;
        return;
      }

      existing.connState = CONNECTION_STATES.PROMOTING;

      const message = encodeMessage({
        msgType: MSG_PING,
        msgFlags: 0
      }, existing.sharedSecret, encodePing());

      await this.send(
        message, externalPort, externalAddr
      );

      await sleep(500);

      existing.connState = CONNECTION_STATES.CONNECTED;

      if ((Date.now() - existing.lastSeen) <= 10000) {
        existing.type = ACTIVE_CONN;
      }
  
      return;
    }

    const connObj = newConnection(ACTIVE_CONN, -1, 0n, null);
    this.connections.set(connStr, connObj);

    let timeout = 500;

    for (var attempt = 0; attempt <= 3; attempt++) {
      const payload = encodeConnection({
        version: PROTOCOl_VERSION,
        magic: NETWORK_MAGIC,
        publicKey: connObj.localPublicKey,
        timestamp: BigInt(Date.now())
      });

      const message = encodeMessage({
        msgType: MSG_CONNECT,
        msgFlags: encodeConnectionFlags(attempt, false)
      }, null, payload);

      await this.send(
        message, externalPort, externalAddr
      );

      await sleep(timeout);

      if (this.didReceiveConn(connStr)) break;

      timeout *= 2;
    }

    if (!this.didReceiveConn(connStr)) {
      console.log("Failed to connect to", connStr);
    }
  }
}

Client.prototype.pingActive = pingActive;
Client.prototype.pingPassive = pingPassive;

Client.prototype.processConnect = processConnect;
Client.prototype.processPing = processPing;

Client.prototype.processMessage = function (connObj, connInfo, message) {
  switch (message.header.msgType) {
    case MSG_PING: {
      this.processPing(connObj, connInfo, message.payload);
      break;
    }

    case MSG_PONG: {
      break;
    }

    default: {
      console.log("Unknown Message", connObj, connInfo, message)
      break;
    }
  }
}

module.exports = Client;