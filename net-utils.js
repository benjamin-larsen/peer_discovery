const ipaddr = require('ipaddr.js');
const { blake3 } = require('@noble/hashes/blake3.js');

function normalizeAddressDetailed(address, port) {
  const addr = ipaddr.process(address);
  let normalized = addr.toNormalizedString();

  if (addr.kind() == "ipv4") {
    return {
      string: `${normalized}:${port}`,
      address: normalized,
      port
    };
  } else {
    return {
      string: `[${normalized}]:${port}`,
      address: normalized,
      port
    };
  }
}

function normalizeAddress(address, port) {
  return normalizeAddressDetailed(address, port).string;
}

function decodeAddress(address) {
  if (address.startsWith("[")) {
    const parts = address.match(/\[(.*)\]:(\d+)/);

    return {
      address: parts[1],
      port: parseInt(parts[2])
    }
  } else {
    const parts = address.split(":");

    return {
      address: parts[0],
      port: parseInt(parts[1])
    }
  }
}

function addressToPeerBuf(addressStr) {
  const { address, port } = decodeAddress(addressStr);

  let parsed = ipaddr.process(address);

  if (parsed.kind() == "ipv4") {
    parsed = parsed.isIPv4MappedAddress();
  }

  const buffer = Buffer.alloc(18);
  buffer.set(Buffer.from(parsed.toByteArray()))
  buffer.writeUInt16LE(port, 16);

  return buffer;
}

function getAddressTopology(address, random) {
  let buf = Buffer.isBuffer(address) ? address : addressToPeerBuf(address);

  const hash = blake3(buf, { key: Buffer.from(random) });

  let sum = 0;

  for (var i = 0; i < 32; i++) {
    sum ^= hash[i];
  }

  return sum & 3;
}

module.exports = {
  normalizeAddressDetailed,
  normalizeAddress,
  decodeAddress,
  addressToPeerBuf,
  getAddressTopology
}