const crypto = require("node:crypto");
const { x25519 } = require("@noble/curves/ed25519.js");
const { CONNECTION_STATES } = require("./constants");

function resetConnection(connObj, externalAttempt = -1, externalTimestamp = 0n, externalPublicKey = null) {
  connObj.lastSeen = 0;
  connObj.lastPing = 0n;
  connObj.externalTimestamp = externalTimestamp;
  connObj.externalAttempt = externalAttempt;
  connObj.externalPublicKey = externalPublicKey;
  connObj.localPrivateKey = crypto.randomBytes(32);
  connObj.localPublicKey = Buffer.from(x25519.getPublicKey(connObj.localPrivateKey));
  connObj.sharedSecret = externalPublicKey ? Buffer.from(x25519.getSharedSecret(connObj.localPrivateKey, externalPublicKey)) : null;
  connObj.connState = externalPublicKey ? CONNECTION_STATES.CONNECTED : CONNECTION_STATES.CONNECTING;
}

function newConnection(type, externalAttempt, externalTimestamp, externalPublicKey) {
  const connObj = {
    lastSeen: 0,
    lastPing: 0n,
    externalTimestamp: 0n,
    externalAttempt: -1,
    externalPublicKey: null,
    localPrivateKey: null,
    localPublicKey: null,
    type,
    connState: CONNECTION_STATES.CONNECTING
  };

  resetConnection(connObj, externalAttempt, externalTimestamp, externalPublicKey);

  return connObj;
}

module.exports = {
  newConnection,
  resetConnection
}