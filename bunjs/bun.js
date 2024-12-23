import { serve } from "bun";

// In-memory user store: Map<email, hashedPassword>
const users = new Map();

// Secret key used for HMAC signing (JWT). 
// For production, load from secure config or environment variable.
const SECRET = "my-secret-key";

/* ------------------------------------------
 * Helpers
 * ------------------------------------------ */

// Quick-and-dirty base64url (for header & payload)
function base64urlEncode(str) {
  // Convert string -> Uint8Array
  const bytes = new TextEncoder().encode(str);
  // Convert bytes -> base64
  let base64 = btoa(String.fromCharCode(...bytes));
  // Replace chars to get base64url
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Synchronous HMAC-SHA256 signing using Bun's built-in hash
function hmacSha256(data, secret) {
  return Bun.hash(data, {
    algorithm: "hmac",
    key: secret,
    encoding: "base64",
  });
}

// Convert normal base64 -> base64url
function toBase64Url(b64) {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Generate a simple JWT { email, iat } signed with HS256
function generateJWT(email) {
  const header = base64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64urlEncode(
    JSON.stringify({ email, iat: Date.now() })
  );

  const signatureBase = `${header}.${payload}`;
  const signature = toBase64Url(hmacSha256(signatureBase, SECRET));

  return `${signatureBase}.${signature}`;
}

// Hash password using plain SHA-256 (for performance demo only)
function hashPassword(password) {
  return Bun.hash(password, { algorithm: "sha256", encoding: "base64" });
}

// Parse JSON from request body
async function parseJsonRequest(req) {
  try {
    return await req.json();
  } catch (e) {
    return null;
  }
}

/* ------------------------------------------
 * Endpoints
 * ------------------------------------------ */

// POST /register
// Body: { email, password }
// Response: { success: true, token: "<jwt>" } or { success: false, message: "<error>" }
async function handleRegister(req) {
  const body = await parseJsonRequest(req);
  if (!body || !body.email || !body.password) {
    return jsonResponse({ success: false, message: "Invalid input" }, 400);
  }

  const { email, password } = body;

  // Check if user already exists
  if (users.has(email)) {
    return jsonResponse({ success: false, message: "User already exists" }, 400);
  }

  // Hash the password and store
  const hashed = hashPassword(password);
  users.set(email, hashed);

  // Return a JWT
  const token = generateJWT(email);
  return jsonResponse({ success: true, token });
}

// POST /login
// Body: { email, password }
// Response: { success: true, token: "<jwt>" } or { success: false, message: "<error>" }
async function handleLogin(req) {
  const body = await parseJsonRequest(req);
  if (!body || !body.email || !body.password) {
    return jsonResponse({ success: false, message: "Invalid input" }, 400);
  }

  const { email, password } = body;

  // Check if user exists
  if (!users.has(email)) {
    return jsonResponse({ success: false, message: "Invalid credentials" }, 401);
  }

  // Compare hashed password
  const storedHash = users.get(email);
  const providedHash = hashPassword(password);

  if (storedHash !== providedHash) {
    return jsonResponse({ success: false, message: "Invalid credentials" }, 401);
  }

  // Return a JWT
  const token = generateJWT(email);
  return jsonResponse({ success: true, token });
}

// POST /delete
// Body: { email }
// Response: { success: true } or { success: false, message: "<error>" }
async function handleDelete(req) {
  const body = await parseJsonRequest(req);
  if (!body || !body.email) {
    return jsonResponse({ success: false, message: "Invalid input" }, 400);
  }

  const { email } = body;
  if (users.has(email)) {
    users.delete(email);
    return jsonResponse({ success: true });
  } else {
    return jsonResponse({ success: false, message: "User does not exist" }, 404);
  }
}

/* ------------------------------------------
 * Server
 * ------------------------------------------ */

// Simple helper for returning JSON responses
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);

    // Only POST is used, route by pathname
    if (req.method === "POST") {
      switch (url.pathname) {
        case "/register":
          return await handleRegister(req);
        case "/login":
          return await handleLogin(req);
        case "/delete":
          return await handleDelete(req);
        default:
          return jsonResponse({ success: false, message: "Not Found" }, 404);
      }
    }

    // If any other method:
    return jsonResponse({ success: false, message: "Not Found" }, 404);
  },
});
