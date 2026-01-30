const { MIN_AUTH_PACKET, HEADER_SIZE } = require("./constants.js");
const { blake3 } = require('@noble/hashes/blake3.js');

const MSG_CONNECT = 0;
const MSG_PING = 1;
const MSG_PONG = 2;
const MSG_REQ_PEERS = 3;
const MSG_PEERS = 4;
const MSG_REQ_CONN = 5;
const MSG_CONN = 6;

function decodeHeader(buffer) {
  return {
    msgType: buffer.readUInt16LE(0),
    msgFlags: buffer.readUInt16LE(2)
  };
}

function encodeHeader({msgType, msgFlags}) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt16LE(msgType, 0);
  buffer.writeUInt16LE(msgFlags, 2);

  return buffer;
}

function isValidMessage(header, payload) {
  switch (header.msgType) {
    case MSG_CONNECT: {
      return payload.length == 52;
    }

    case MSG_PING: {
      return payload.length == 8;
    }

    case MSG_REQ_PEERS:
    case MSG_PONG: {
      return payload.length == 0;
    }

    case MSG_PEERS: {
      return true;
    }

    default: {
      return false;
    }
  }
}

function decodeMessage(buffer) {
  const header = decodeHeader(buffer);
  const hasSignature = header.msgType != MSG_CONNECT;

  if (hasSignature && buffer.length < MIN_AUTH_PACKET) throw Error("Invalid Message");

  const signature = hasSignature ? buffer.subarray(HEADER_SIZE, MIN_AUTH_PACKET) : null;
  const payload = buffer.subarray(hasSignature ? MIN_AUTH_PACKET : HEADER_SIZE);

  if (!isValidMessage(header, payload)) throw Error("Invalid Message");

  return {
    header,
    signature,
    payload
  }
}


function encodeMessage(header, sharedSecret, payload) {
  const expectSignature = header.msgType != MSG_CONNECT;

  if (expectSignature && (!Buffer.isBuffer(sharedSecret) || sharedSecret.length != 32)) throw Error("Invalid Message");
  if (!expectSignature && sharedSecret) throw Error("Invalid Message");

  const headerBuf = encodeHeader(header);

  const signature = expectSignature ? blake3.create({ key: Buffer.from(sharedSecret) })
            .update(headerBuf)
            .update(payload)
            .digest() : null;
  
  return Buffer.concat([
    headerBuf,
    signature || Buffer.alloc(0),
    payload
  ])
}

module.exports = {
  encodeMessage,
  decodeMessage,
  MSG_CONNECT,
  MSG_PING,
  MSG_PONG,
  MSG_REQ_PEERS,
  MSG_PEERS,
  MSG_REQ_CONN,
  MSG_CONN
};