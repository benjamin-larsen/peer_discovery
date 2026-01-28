const ipaddr = require('ipaddr.js');

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

module.exports = {
  normalizeAddressDetailed,
  normalizeAddress,
  decodeAddress
}