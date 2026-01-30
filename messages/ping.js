const { CONNECTION_FLAGS, ACTIVE_CONN, PASSIVE_CONN } = require("../constants.js");
const { encodeMessage, MSG_PONG, MSG_PING } = require("../messages.js");
const { decodeAddress } = require("../net-utils.js");
const { isTimestampValid, sleep } = require("../utils.js");

function encodePing() {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(Date.now()));

  return buffer;
}

function decodePing(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length != 8) throw Error("Invalid Buffer");

  return buffer.readBigUInt64LE();
}

function processPing(connObj, connInfo, payload) {
  const timestamp = decodePing(payload);
  console.log("Received Ping", timestamp, connInfo.string);

  if (!isTimestampValid(timestamp))
    throw Error("Invalid Timestamp");

  if (timestamp <= connObj.lastPing) throw Error("Duplicate packet");

  connObj.lastPing = timestamp;

  const response = encodeMessage({
    msgType: MSG_PONG,
    msgFlags: 0
  }, connObj.sharedSecret, Buffer.alloc(0));

  this.send(response, connInfo.port, connInfo.address);
}

async function pingGroup(client, timeLimit, type, attempts, onFail) {
  const activeConnections = [...client.connections].filter(([_, connection]) => {
    if ((connection.flags & (CONNECTION_FLAGS.CONNECTED | CONNECTION_FLAGS.PING_LOCKED)) !== CONNECTION_FLAGS.CONNECTED) return;
    if (connection.type !== type) return false;

    // Lock connection
    connection.flags |= CONNECTION_FLAGS.PING_LOCKED;

    return true;
  });

  let timeout = 500;

  for (var i = 0; i < attempts; i++) {
    const now = Date.now();

    for (const index in activeConnections) {
      if (!activeConnections[index]) continue;

      const [connStr, connection] = activeConnections[index];

      const timeDiff = now - connection.lastSeen;

      if (timeDiff < timeLimit) {
        // Unlock connection
        connection.flags &= ~CONNECTION_FLAGS.PING_LOCKED;

        activeConnections[index] = null;
        continue;
      }

      const { address, port } = decodeAddress(connStr);

      client.send(encodeMessage({
        msgType: MSG_PING,
        msgFlags: 0
      }, connection.sharedSecret, encodePing()), port, address);
    }

    await sleep(timeout);

    timeout *= 2;
  }

  const now = Date.now();

  for (const index in activeConnections) {
    if (!activeConnections[index]) continue;

    const [connStr, connection] = activeConnections[index];

    const timeDiff = now - connection.lastSeen;

    // Unlock connection
    connection.flags &= ~CONNECTION_FLAGS.PING_LOCKED;

    if (timeDiff >= 10000) {
      onFail(client, connStr, connection);
    }
  }
}

function demoteActive(client, connStr, connection) {
  console.log("Demote Active", connStr);
  connection.type = PASSIVE_CONN;
}

function evictPassive(client, connStr, connection) {
  console.log("Evict Passive", connStr);
  client.connections.delete(connStr);
}

function pingActive() {
  pingGroup(this, 10000, ACTIVE_CONN, 2, demoteActive)
}

function pingPassive() {
  pingGroup(this, 60000, PASSIVE_CONN, 4, evictPassive)
}

module.exports = {
  encodePing,
  decodePing,
  processPing,
  pingActive,
  pingPassive
};