const crypto = require("node:crypto");
const { x25519 } = require("@noble/curves/ed25519.js");
const { CONNECTION_FLAGS } = require("./constants");

function resetConnection(connObj, externalAttempt = -1, externalTimestamp = 0n, externalPublicKey = null) {
  connObj.flags = 0;
  connObj.lastSeen = 0;
  connObj.lastPing = 0n;
  connObj.externalTimestamp = externalTimestamp;
  connObj.externalAttempt = externalAttempt;
  connObj.localPrivateKey = crypto.randomBytes(32);
  connObj.localPublicKey = Buffer.from(x25519.getPublicKey(connObj.localPrivateKey));

  if (externalPublicKey) {
    connObj.flags |= CONNECTION_FLAGS.CONNECTED;
    connObj.externalPublicKey = externalPublicKey;
    connObj.sharedSecret = Buffer.from(x25519.getSharedSecret(connObj.localPrivateKey, externalPublicKey));
  } else {
    connObj.externalPublicKey = null;
    connObj.sharedSecret = null;
  }
}

function newConnection(type, externalAttempt, externalTimestamp, externalPublicKey) {
  const connObj = {
    flags: 0,
    lastSeen: 0,
    lastPing: 0n,
    externalTimestamp: 0n,
    externalAttempt: -1,
    externalPublicKey: null,
    localPrivateKey: null,
    localPublicKey: null,
    type
  };

  resetConnection(connObj, externalAttempt, externalTimestamp, externalPublicKey);

  return connObj;
}

module.exports = {
  newConnection,
  resetConnection
}