const ipaddr = require('ipaddr.js');
const { CONNECTION_FLAGS, MAX_ACTIVE, ACTIVE_CONN, PASSIVE_CONN } = require("../constants.js");
const { encodeMessage, MSG_PEERS, MSG_REQ_PEERS } = require("../messages.js");
const { decodeAddress, addressToPeerBuf } = require("../net-utils.js");

function encodePeerRequestFlags({
  active,
  total
}) {
  if (total < 0 || total > 50) throw Error("'total' must be bewteen 0 and 50.");
  if (active < 0) throw Error("'active' must be a positive number.");
  if (active > total) throw Error("'active' must be less than or equal to 'total'.");

  return active << 8 | total;
}

function decodePeerRequestFlags(flags) {
  if (flags < 0 || flags > 0xffff) throw Error("Invalid flags.");

  const active = flags >> 8;
  const total = flags & 0xff;

  if (total > 50) throw Error("'active' must be less than or equal 50.");
  if (active > total) throw Error("'active' must be less than or equal to 'total'.");

  return {
    active,
    total
  }
}

function encodePeerChunkFlags({
  active,
  passive
}) {
  return active << 8 | passive;
}

function decodePeerChunkFlags(flags) {
  if (flags < 0 || flags > 0xffff) throw Error("Invalid flags.");

  const active = flags >> 8;
  const passive = flags & 0xff;

  return {
    active,
    passive
  }
}

function fetchPeers() {
  // also attempt to promote some passive here
  if (this.activeCount() >= MAX_ACTIVE) return;

  for (const [connStr, connection] of this.connections) {
    if (connection.type !== ACTIVE_CONN) continue;
    if ((connection.flags & CONNECTION_FLAGS.CONNECTED) == 0) continue;

    connection.flags |= CONNECTION_FLAGS.EXPECTING_PEERS;

    const { address, port } = decodeAddress(connStr);

    this.send(encodeMessage({
      msgType: MSG_REQ_PEERS,
      msgFlags: encodePeerRequestFlags({
        active: MAX_ACTIVE,
        total: 50
      })
    }, connection.sharedSecret, Buffer.alloc(0)), port, address);
  }
}

function shuffle(array) {
  let currentIndex = array.length;

  while (currentIndex != 0) {

    let randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    [array[currentIndex], array[randomIndex]] = [
      array[randomIndex], array[currentIndex]];
  }

  return array;
}

function processPeerReq(connObj, connInfo, flags) {
  const { active: reqActive, total: reqTotal } = decodePeerRequestFlags(flags);

  let left = reqTotal;

  const active = shuffle([...this.connections].filter(([connStr, connection]) => {
    if (connStr == connInfo.string) return false;
    if (connection.type !== ACTIVE_CONN) return false;
    if ((connection.flags & CONNECTION_FLAGS.CONNECTED) == 0) return false;

    return true;
  }).map(([connStr, _]) => connStr));

  const passive = shuffle([...this.connections].filter(([connStr, connection]) => {
    if (connStr == connInfo.string) return false;
    if (connection.type !== PASSIVE_CONN) return false;
    if ((connection.flags & CONNECTION_FLAGS.CONNECTED) == 0) return false;

    return true;
  }).map(([connStr, _]) => connStr));

  const activeRes = [];
  const passiveRes = [];

  for (var i = 0; i < reqActive; i++) {
    const next = active.shift();
    if (!next) break;

    activeRes.push(next);
    left--;
  }

  while (left > 0) {
    const next = passive.shift();
    if (!next) break;

    passiveRes.push(next);
    left--;
  }

  if (activeRes.length == 0 && passiveRes.length == 0) return;

  const bufs = [];

  for (const address of activeRes) {
    bufs.push(addressToPeerBuf(address))
  }

  for (const address of passiveRes) {
    bufs.push(addressToPeerBuf(address))
  }

  this.send(encodeMessage({
    msgType: MSG_PEERS,
    msgFlags: encodePeerChunkFlags({
      active: activeRes.length,
      passive: passiveRes.length
    })
  }, connObj.sharedSecret, Buffer.concat(bufs)), connInfo.port, connInfo.address)
}

function processPeerChunk(connObj, connInfo, message) {
  const { active, passive } = decodePeerChunkFlags(message.header.msgFlags);
  const total = active + passive;

  if (total > 50) return;
  if (message.payload.length != (total * 18)) return;

  for (var i = 0; i < message.payload.length; i += 18) {
    const buf = message.payload.subarray(i, i + 18);

    const address = ipaddr.fromByteArray(buf.subarray(0, 16)).toNormalizedString();
    const port = buf.readUInt16LE(16);

    this.connect(address, port);
  }
}

module.exports = {
  fetchPeers,
  processPeerReq,
  processPeerChunk,
  decodePeerChunkFlags
};