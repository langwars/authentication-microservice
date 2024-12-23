/**
 * Minimal Authentication Microservice in Node.js
 * ----------------------------------------------
 * Endpoints:
 *   1) POST /register
 *   2) POST /login
 *   3) DELETE /delete
 *
 * Stores users in-memory as { email: hashedPassword }.
 * Returns a JWT on successful register/login, which includes the user email.
 * Verifies the JWT before allowing /delete.
 * Passwords are hashed in-memory with a simple HMAC-SHA256 (no salt, minimal overhead).
 * Uses only native Node.js modules: http, crypto, url.
 */

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

// -------------------------------------------------------------------------
// Configuration & Storage
// -------------------------------------------------------------------------
const PORT = 3000;                         // Port for the HTTP server
const SECRET_KEY = 'YOUR_SUPER_SECRET';    // Secret key for HMAC signing
const users = Object.create(null);         // In-memory user store: { email: hashedPassword }

// -------------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------------

/**
 * Safely parse JSON from the request body.
 * Returns a Promise that resolves to an object with { success, data }.
 */
function parseJSONBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        resolve({ success: true, data });
      } catch (e) {
        resolve({ success: false, data: null });
      }
    });
  });
}

/**
 * Send a JSON response with a given status code and object data.
 */
function sendJSON(res, statusCode, obj) {
  const json = JSON.stringify(obj);
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(json);
}

/**
 * Hash a password using a simple HMAC-SHA256 with SECRET_KEY.
 */
function hashPassword(password) {
  return crypto
    .createHmac('sha256', SECRET_KEY)
    .update(password)
    .digest('hex');
}

/**
 * Create a base64 URL-safe string.
 */
function base64UrlEncode(buf) {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Generate a JWT with the HS256 algorithm (HMAC-SHA256).
 * The payload should include user email, plus any other claims.
 */
function generateJWT(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload)));

  const signatureData = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(signatureData)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Verify a JWT and return the decoded payload if valid, or null if invalid.
 */
function verifyJWT(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [encodedHeader, encodedPayload, signature] = parts;
  const signatureData = `${encodedHeader}.${encodedPayload}`;

  // Recompute signature
  const expectedSignature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(signatureData)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  // Compare signatures
  if (signature !== expectedSignature) return null;

  // Decode payload
  try {
    const payload = JSON.parse(
      Buffer.from(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()
    );
    return payload;
  } catch (err) {
    return null;
  }
}

// -------------------------------------------------------------------------
// Request Handlers
// -------------------------------------------------------------------------

async function handleRegister(req, res) {
  const { success, data } = await parseJSONBody(req);
  if (!success || !data.email || !data.password) {
    return sendJSON(res, 400, { error: 'Invalid JSON or missing fields.' });
  }

  const { email, password } = data;
  if (users[email]) {
    return sendJSON(res, 400, { error: 'User already exists.' });
  }

  // Hash and store password
  const hashed = hashPassword(password);
  users[email] = hashed;

  // Return JWT
  const token = generateJWT({ email });
  sendJSON(res, 200, { token });
}

async function handleLogin(req, res) {
  const { success, data } = await parseJSONBody(req);
  if (!success || !data.email || !data.password) {
    return sendJSON(res, 400, { error: 'Invalid JSON or missing fields.' });
  }

  const { email, password } = data;
  const userHashed = users[email];
  if (!userHashed) {
    return sendJSON(res, 401, { error: 'Invalid credentials.' });
  }

  const givenHashed = hashPassword(password);
  if (userHashed !== givenHashed) {
    return sendJSON(res, 401, { error: 'Invalid credentials.' });
  }

  // Return JWT
  const token = generateJWT({ email });
  sendJSON(res, 200, { token });
}

async function handleDelete(req, res) {
  // The DELETE endpoint will look for a JWT in the Authorization header:
  //   Authorization: Bearer <JWT>
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return sendJSON(res, 401, { error: 'Missing Authorization header.' });
  }

  const parts = authHeader.split(' ');
  if (parts[0] !== 'Bearer' || !parts[1]) {
    return sendJSON(res, 401, { error: 'Malformed Authorization header.' });
  }

  const token = parts[1];
  const payload = verifyJWT(token);
  if (!payload || !payload.email) {
    return sendJSON(res, 401, { error: 'Invalid or expired token.' });
  }

  // Attempt to delete user
  if (users[payload.email]) {
    delete users[payload.email];
    return sendJSON(res, 200, { success: true });
  } else {
    return sendJSON(res, 400, { success: false, error: 'User not found.' });
  }
}

// -------------------------------------------------------------------------
// Main HTTP Server
// -------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  // Parse the URL and method
  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  const pathname = urlObj.pathname;
  const method = req.method.toUpperCase();

  if (pathname === '/register' && method === 'POST') {
    return handleRegister(req, res);
  }

  if (pathname === '/login' && method === 'POST') {
    return handleLogin(req, res);
  }

  if (pathname === '/delete' && method === 'DELETE') {
    return handleDelete(req, res);
  }

  // Fallback for unknown routes
  sendJSON(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`Authentication microservice running at http://localhost:${PORT}/`);
});
