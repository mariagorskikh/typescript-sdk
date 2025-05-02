// test-coupon-demo.js
process.env.DEBUG_COUPON = '1';
const fs = require('fs');
const path = require('path');
const http = require('http');
const { generateKeyPair, verifyInteractionCoupon, signPayload, hashPayload } = require('./dist/esm/shared/crypto.js');
const { McpServer } = require('./dist/esm/server/mcp.js');
const { z } = require('zod');

// 1. Generate key pair if not present
const privPath = path.resolve(__dirname, 'server_private.pem');
const pubPath = path.resolve(__dirname, 'server_public.pem');
let privateKey, publicKey;
if (!fs.existsSync(privPath) || !fs.existsSync(pubPath)) {
  const keys = generateKeyPair();
  fs.writeFileSync(privPath, keys.privateKey);
  fs.writeFileSync(pubPath, keys.publicKey);
  privateKey = keys.privateKey;
  publicKey = keys.publicKey;
  console.log('Generated new key pair.');
} else {
  privateKey = fs.readFileSync(privPath, 'utf8');
  publicKey = fs.readFileSync(pubPath, 'utf8');
}

// 2. Start a minimal MCP server with coupon signing enabled
const PORT = 4000;
const server = new McpServer(
  { name: 'DemoServer', version: '1.0.0' },
  { interactionCouponPrivateKey: privateKey }
);

// Register a simple tool
server.tool('echo', { input: z.string() }, async ({ input }) => ({
  content: [{ type: 'text', text: input }],
}));

const httpServer = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/mcp') {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', async () => {
      try {
        const json = JSON.parse(body);
        // Connect a new transport for each request (stateless demo)
        const { StreamableHTTPServerTransport } = require('./dist/esm/server/streamableHttp.js');
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined, // stateless mode
          enableJsonResponse: true
        });
        await server.connect(transport);
        await transport.handleRequest(req, res, json);
      } catch (e) {
        res.writeHead(500).end(JSON.stringify({ error: e.message }));
      }
    });
  } else {
    res.writeHead(404).end('Not found');
  }
});

httpServer.listen(PORT, async () => {
  console.log(`Demo MCP server running on http://localhost:${PORT}/mcp`);

  // 3. Send a request to the server
  const requestPayload = {
    jsonrpc: '2.0',
    id: '1',
    method: 'tools/call',
    params: { name: 'echo', arguments: { input: 'Hello, world!' }, caller_id: 'test-client' },
  };
  const req = http.request(
    {
      hostname: 'localhost',
      port: PORT,
      path: '/mcp',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream' },
    },
    (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          console.log('Full raw response:', data);
          if (response.result) {
            console.log('Result object:', JSON.stringify(response.result, null, 2));
          }
          const coupon =
            response.result &&
            response.result._meta &&
            response.result._meta.interaction_coupon;
          if (!coupon) {
            console.error('No coupon found in response!');
            process.exit(1);
          }
          // Remove coupon from response for hash verification
          const responseForHash = JSON.parse(JSON.stringify(response.result));
          if (responseForHash._meta && responseForHash._meta.interaction_coupon) {
            delete responseForHash._meta.interaction_coupon;
          }
          if (responseForHash._meta && Object.keys(responseForHash._meta).length === 0) {
            delete responseForHash._meta;
          }
          // Utility to recursively sort all keys in an object
          function sortKeys(obj) {
            if (Array.isArray(obj)) return obj.map(sortKeys);
            if (obj && typeof obj === 'object') {
              return Object.keys(obj).sort().reduce((acc, key) => {
                acc[key] = sortKeys(obj[key]);
                return acc;
              }, {});
            }
            return obj;
          }
          // Print JSON used for hashing
          const reqJson = JSON.stringify(sortKeys(requestPayload));
          const resJson = JSON.stringify(sortKeys(responseForHash));
          console.log('[DEBUG] Client-side request JSON for hash:', reqJson);
          console.log('[DEBUG] Client-side response JSON for hash:', resJson);
          const reqHash = require('./dist/esm/shared/crypto.js').hashPayload(sortKeys(requestPayload));
          const resHash = require('./dist/esm/shared/crypto.js').hashPayload(sortKeys(responseForHash));
          console.log('[DEBUG] Client-side request hash:', reqHash);
          console.log('[DEBUG] Client-side response hash:', resHash);
          const valid = verifyInteractionCoupon(
            coupon,
            requestPayload,
            responseForHash,
            publicKey
          );
          console.log('Response:', response);
          console.log('Coupon valid?', valid);
          console.log('Full response:', JSON.stringify(response, null, 2));
          console.log('Request object for verification:', JSON.stringify(requestPayload, null, 2));
          console.log('Response object for verification:', JSON.stringify(responseForHash, null, 2));
          process.exit(valid ? 0 : 2);
        } catch (e) {
          console.error('Error verifying coupon:', e);
          process.exit(1);
        }
      });
    }
  );
  req.write(JSON.stringify(requestPayload));
  req.end();
}); 