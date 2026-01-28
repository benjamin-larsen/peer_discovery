const Client = require("./client.js");

const bootstrap = new Client(() => {}, "::1", 1000)
const client = new Client(() => {}, "::1", 1001)
client.connect("::1", 1000)
