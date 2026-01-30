const crypto = require("node:crypto");
const dgram = require("node:dgram");
const { normalizeAddressDetailed, decodeAddress, getAddressTopology, normalizeAddress } = require("./net-utils.js");
const { sleep } = require("./utils.js");
const { blake3 } = require('@noble/hashes/blake3.js');
const { ACTIVE_CONN, HEADER_SIZE, MAX_PACKET, PASSIVE_CONN, PROTOCOl_VERSION, NETWORK_MAGIC, CONNECTION_FLAGS, MAX_ACTIVE, MAX_ACTIVE_INTERNAL, MAX_ACTIVE_EXTERNAL } = require("./constants.js");
const { decodeMessage, encodeMessage, MSG_CONNECT, MSG_PING, MSG_PONG, MSG_REQ_PEERS, MSG_PEERS } = require("./messages.js");
const { newConnection } = require("./connectManager.js");
const { encodeConnectionFlags, encodeConnection, processConnect } = require("./messages/connect.js");
const { encodePing, processPing, pingActive, pingPassive } = require("./messages/ping.js");
const { fetchPeers, processPeerReq, processPeerChunk } = require("./messages/peers.js");

class Client {
  constructor(getTcpInfo, udpAddr, udpPort, bindCb) {
    this.connections = new Map();

    this.getTcpInfo = getTcpInfo;
    this.udpAddr = udpAddr;
    this.udpPort = udpPort;

    this.udpServer = dgram.createSocket({ type: 'udp6' });
    this.udpServer.bind(udpPort, udpAddr, bindCb);

    this.topologySeed = crypto.randomBytes(32);
    this.topology = getAddressTopology(
      normalizeAddress(udpAddr, udpPort),
      this.topologySeed
    );

    this.pingLoop = setInterval(() => {
      this.pingActive();

      setTimeout(() => {
        this.pingPassive();
      }, 1000);
    }, 30000);

    this.discoveryLoop = setInterval(() => {
      this.fetchPeers()
    }, 30000);

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

  destroy() {
    if (this.pingLoop) {
      clearInterval(this.pingLoop);
      this.pingLoop = null;
    }

    if (this.udpServer) {
      this.udpServer.close();
      //this.udpServer = null;
    }
  }

  activeCount() {
    let count = 0;

    for (const [_, connection] of this.connections) {
      if (connection.type !== ACTIVE_CONN) continue;

      count++;
    }

    return count;
  }

  activeInternalCount() {
    let count = 0;

    for (const [connStr, connection] of this.connections) {
      if (connection.type !== ACTIVE_CONN) continue;
      if (getAddressTopology(
        connStr,
        this.topologySeed
      ) !== this.topology) continue;

      count++;
    }

    return count;
  }

  activeExternalCount() {
    let count = 0;

    for (const [connStr, connection] of this.connections) {
      if (connection.type !== ACTIVE_CONN) continue;
      if (getAddressTopology(
        connStr,
        this.topologySeed
      ) === this.topology) continue;

      count++;
    }

    return count;
  }

  send(buf, port, address) {
    return new Promise((resolve, reject) => {
      this.udpServer.send(buf, port, address, (err) => {
        if (err) return reject(err);
        resolve();
      })
    })
  }

  isConnected(connStr) {
    const existing = this.connections.get(connStr);
    if (!existing) return false;

    return (existing.flags & CONNECTION_FLAGS.CONNECTED) != 0;
  }

  async connect(rawAddr, externalPort) {
    if (this.activeCount() >= MAX_ACTIVE) return;

    const { address: externalAddr, string: connStr } = normalizeAddressDetailed(rawAddr, externalPort);

    const topology = getAddressTopology(
      connStr,
      this.topologySeed
    );

    const isInternal = topology === this.topology;

    if (isInternal && this.activeInternalCount() >= MAX_ACTIVE_INTERNAL) return;
    if (!isInternal && this.activeExternalCount() >= MAX_ACTIVE_EXTERNAL) return;

    const existing = this.connections.get(connStr);

    if (existing) {
      if (existing.type === ACTIVE_CONN) return;

      // Check that Connection is not Ping Locked, and is Connected. Might need a way to promote after Ping is over.
      if ((existing.flags & (CONNECTION_FLAGS.CONNECTED | CONNECTION_FLAGS.PING_LOCKED)) !== CONNECTION_FLAGS.CONNECTED) return;

      console.log("Promoting", connStr, existing);

      if ((Date.now() - existing.lastSeen) <= 10000) {
        existing.type = ACTIVE_CONN;
        return;
      }

      existing.flags |= CONNECTION_FLAGS.PING_LOCKED;

      const message = encodeMessage({
        msgType: MSG_PING,
        msgFlags: 0
      }, existing.sharedSecret, encodePing());

      await this.send(
        message, externalPort, externalAddr
      );

      await sleep(500);

      existing.flags &= ~CONNECTION_FLAGS.PING_LOCKED;

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

      if (this.isConnected(connStr)) break;

      timeout *= 2;
    }

    if (!this.isConnected(connStr)) {
      console.log("Failed to connect to", connStr);
      this.connections.delete(connStr);
    }
  }
}

Client.prototype.fetchPeers = fetchPeers;

Client.prototype.pingActive = pingActive;
Client.prototype.pingPassive = pingPassive;

Client.prototype.processConnect = processConnect;
Client.prototype.processPing = processPing;
Client.prototype.processPeerReq = processPeerReq;
Client.prototype.processPeerChunk = processPeerChunk;

Client.prototype.processMessage = function (connObj, connInfo, message) {
  switch (message.header.msgType) {
    case MSG_PING: {
      this.processPing(connObj, connInfo, message.payload);
      break;
    }

    case MSG_PONG: {
      break;
    }

    case MSG_REQ_PEERS: {
      this.processPeerReq(connObj, connInfo, message.header.msgFlags);
      break;
    }

    case MSG_PEERS: {
      this.processPeerChunk(connObj, connInfo, message);
      break;
    }

    default: {
      console.log("Unknown Message", connObj, connInfo, message)
      break;
    }
  }
}

module.exports = Client;