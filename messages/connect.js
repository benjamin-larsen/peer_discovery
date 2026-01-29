const { newConnection, resetConnection } = require("../connectManager.js");
const { NETWORK_MAGIC, PASSIVE_CONN, PROTOCOl_VERSION, CONNECTION_STATES } = require("../constants.js");
const { encodeMessage, MSG_CONNECT } = require("../messages.js");
const { x25519 } = require("@noble/curves/ed25519.js");
const { isTimestampValid } = require("../utils.js");

function encodeConnectionFlags(attempts, receivedConn) {
  if (attempts < 0 || attempts > 15) throw Error("'attempts' must be between 0 and 15.");
  
  return attempts << 1 | !!receivedConn;
}

function decodeConnectionFlags(flags) {
  if (flags < 0 || flags > 0xffff) throw Error("Invalid flags.");
  
  return {
    attempts: (flags >> 1) & 0b1111,
    receivedConn: (flags & 0b1) != 0
  };
}

function encodeConnection({
  version,
  magic,
  publicKey,
  timestamp
}) {
  if (!Buffer.isBuffer(publicKey) || publicKey.length != 32) throw Error("Invalid Public Key");

  const buffer = Buffer.alloc(52);
  buffer.writeUInt32LE(version, 0);
  buffer.writeBigUInt64LE(magic, 4);
  buffer.set(publicKey, 12);
  buffer.writeBigUInt64LE(timestamp, 44);

  return buffer;
}

function decodeConnection(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length != 52) throw Error("Invalid Buffer");

  return {
    version: buffer.readUInt32LE(0),
    magic: buffer.readBigUInt64LE(4),
    publicKey: buffer.subarray(12, 44),
    timestamp: buffer.readBigUInt64LE(44)
  };
}

function processConnect(connInfo, message) {
  const flags = decodeConnectionFlags(message.header.msgFlags);
  const payload = decodeConnection(message.payload);

  if (!isTimestampValid(payload.timestamp))
    throw Error("Invalid Timestamp");

  if (payload.magic != NETWORK_MAGIC) throw Error("Invalid Network");

  let isNew = false;
  let connObj = this.connections.get(connInfo.string);

  if (connObj && connObj.localPublicKey.equals(payload.publicKey)) throw Error("Connected to self");

  if (!connObj) {
    isNew = true;
    connObj = newConnection(PASSIVE_CONN, flags.attempts, payload.timestamp, payload.publicKey);
    this.connections.set(connInfo.string, connObj);
  }

  if (!isNew) {
    if (connObj.externalPublicKey && !connObj.externalPublicKey.equals(payload.publicKey)) {
      if (connObj.externalTimestamp >= payload.timestamp) throw Error("Duplicate Packet");
      console.log("Swapped Connection");
      resetConnection(connObj, flags.attempts, payload.timestamp, payload.publicKey);

      // Ignore Received Connection, send new one.
      flags.receivedConn = false;
    } else if (connObj.externalAttempt >= flags.attempts) throw Error("Duplicate Packet");
  }

  if (!connObj.externalPublicKey) {
    connObj.externalPublicKey = payload.publicKey;
  }

  if (connObj.externalPublicKey && !connObj.sharedSecret) {
    connObj.sharedSecret = Buffer.from(x25519.getSharedSecret(connObj.localPrivateKey, connObj.externalPublicKey));
  }

  connObj.externalTimestamp = payload.timestamp;
  connObj.externalAttempt = flags.attempts;
  connObj.connState = CONNECTION_STATES.CONNECTED;

  if (!flags.receivedConn) {
    const payload = encodeConnection({
      version: PROTOCOl_VERSION,
      magic: NETWORK_MAGIC,
      publicKey: connObj.localPublicKey,
      timestamp: BigInt(Date.now())
    });

    const message = encodeMessage({
      msgType: MSG_CONNECT,
      msgFlags: encodeConnectionFlags(0, true)
    }, null, payload);

    this.send(
      message, connInfo.port, connInfo.address
    )
  }
}

module.exports = {
  encodeConnectionFlags,
  decodeConnectionFlags,
  encodeConnection,
  decodeConnection,
  processConnect
}