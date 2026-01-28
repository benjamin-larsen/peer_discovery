function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  })
}

function isTimestampValid(timestamp) {
  const nowTimestamp = BigInt(Date.now());
  const isPast = nowTimestamp > timestamp;
  const diff = isPast ? nowTimestamp - timestamp : timestamp - nowTimestamp;

  if ((isPast && diff >= 60000n) || (!isPast && diff >= 5000n))
    return false;

  return true;
}

module.exports = {
  sleep,
  isTimestampValid
};