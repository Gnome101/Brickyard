#!/usr/bin/env node
/**
 * Lightweight mock of the Snowflake generation endpoint.
 *
 * Usage:
 *   node scripts/mock-snowflake.js [port]
 *
 * The mock accepts POST / with { prompt, agent_type, seed } and returns a
 * deterministic model array that satisfies the worker's validator. This allows
 * you to exercise the worker end-to-end without hitting the real upstream.
 */

const http = require("node:http");

const port = Number(process.argv[2]) || 8788;

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Method not allowed" }));
    return;
  }

  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }

  let body = {};
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch (error) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid JSON body" }));
    return;
  }

  const prompt = typeof body.prompt === "string" ? body.prompt : "demo";
  const agentType = typeof body.agent_type === "string" ? body.agent_type : "A";
  const seed = Number.isFinite(body.seed) ? body.seed : Date.now();

  const model = buildMockModel(prompt, agentType, seed);

  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ model }));
});

server.listen(port, () => {
  console.log(`Mock Snowflake listening on http://127.0.0.1:${port}`);
});

function buildMockModel(prompt, agentType, seed) {
  const baseColor = Math.abs(hashCode(`${agentType}|${prompt}`)) % 256;
  const offset = (hashCode(prompt) % 10) * 4;
  const height = ((seed % 5) + agentType.length) * 8;

  return [
    { ldraw_part: "3001.dat", color: baseColor, pos: [offset, 0, 0], rot: [0, 0, 0] },
    { ldraw_part: "3020.dat", color: (baseColor + 5) % 256, pos: [offset + 20, 0, 0], rot: [0, 0, 0] },
    { ldraw_part: "3004.dat", color: (baseColor + 9) % 256, pos: [offset + 10, height, 0], rot: [0, 0, 0] },
  ];
}

function hashCode(value) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash |= 0;
  }
  return hash;
}
