const { encodeMessage, MSG_PONG } = require("../messages.js");
const { isTimestampValid } = require("../utils.js");

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

function pingLoop() {
  
}

module.exports = {
  encodePing,
  decodePing,
  processPing
};