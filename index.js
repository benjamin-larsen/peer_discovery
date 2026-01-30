const Client = require("./client.js");
const { decodeAddress, normalizeAddress, getAddressTopology } = require("./net-utils.js");

let clients = new Map();

const bootstrap = new Client(() => {}, "::1", 1000);
clients.set(1000, bootstrap);

function createClient() {
  const client = new Client(() => {}, "::1", 0, () => {
    const { port } = client.udpServer.address();
    client.udpPort = port;
    client.topology = getAddressTopology(
      normalizeAddress(client.udpAddr, client.udpPort),
      client.topologySeed
    );

    clients.set(port, client);

    client.connect("::1", 1000);
  });
}

createClient();

const express = require("express");
const { ACTIVE_CONN, PASSIVE_CONN } = require("./constants.js");
const app = express();

app.use("/", (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*")
  next()
})

app.get("/", (req, res) => {
  const nodes = new Set();
  const edges = [];

  for (const [port, client] of clients) {
    nodes.add(port);

    for (const [connStr, { type }] of client.connections) {
      //if (type !== ACTIVE_CONN) continue;

      const { port: otherPort } = decodeAddress(connStr);
      edges.push({ source: `Node ${otherPort}`, target: `Node ${port}`, value: type === ACTIVE_CONN ? 5 : 1 })
    }
  }

  res.status(200).send({
    nodes: [...nodes].map(id => ({id: `Node ${id}`, group: clients.get(id).destroyed ? 3 : id == 1000 ? 1 : 2})),
    links: edges
  })
})

app.get("/node-states", (req, res) => {
  const states = {};

  for (const [port, client] of clients) {
    let active = 0;
    let passive = 0;
    let unknown = 0;

    for (const [_, connection] of client.connections) {
      if (connection.type == ACTIVE_CONN) {
        active++
      } else if (connection.type == PASSIVE_CONN) {
        passive++
      } else {
        unknown++
      }
    }
    states[`Node ${port}`] = {
      active, passive, unknown
    }
  }
  res.status(200).send(states);
})

app.get("/add-node", (req, res) => {
  createClient();
  res.sendStatus(200);
})

app.get("/remove-node/:id", (req, res) => {
  const client = clients.get(parseInt(req.params.id));

  if (!client) return res.sendStatus(404);

  client.destroyed = true;
  client.connections.clear();
  client.destroy();

  res.sendStatus(200);
})

app.listen(5000);