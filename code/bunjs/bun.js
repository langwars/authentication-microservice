import { serve } from "bun";

// In-memory user store: Map<email, hashedPassword>
const users = new Map();

// Secret key for HMAC signing (JWT)
const SECRET = "my-secret-key";

/* ------------------------------------------
 * Helpers
 * ------------------------------------------ */

// Convert string -> base64url
function base64urlEncode(str) {
  // Convert string -> Uint8Array
  const bytes = new TextEncoder().encode(str);
  // Convert bytes -> base64
  let base64 = btoa(String.fromCharCode(...bytes));
  // Replace chars to get base64url
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Convert normal base64 -> base64url
function toBase64Url(b64) {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Convert base64url -> normal base64
function fromBase64Url(b64url) {
  return b64url.replace(/-/g, "+").replace(/_/g, "/");
}

// HMAC-SHA256 using Bun.CryptoHasher
function hmacSha256(data, secret) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(secret);
  hasher.update(data);
  return hasher.digest("base64");
}

// Generate a simple JWT { email, iat }
function generateJWT(email) {
  const header = base64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64urlEncode(JSON.stringify({ email, iat: Date.now() }));

  const signatureBase = `${header}.${payload}`;
  const signature = toBase64Url(hmacSha256(signatureBase, SECRET));

  return `${signatureBase}.${signature}`;
}

// Verify JWT
function verifyJWT(token) {
  // token should be header.payload.signature
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerB64Url, payloadB64Url, signatureB64Url] = parts;
  const signatureBase = `${headerB64Url}.${payloadB64Url}`;
  const expectedSig = toBase64Url(hmacSha256(signatureBase, SECRET));
  if (expectedSig !== signatureB64Url) return null;

  // Decode payload
  try {
    const payloadStr = atob(fromBase64Url(payloadB64Url));
    return JSON.parse(payloadStr);
  } catch {
    return null;
  }
}

// Hash password using Bun.password
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
async function handleRegister(req) {
  const body = await parseJsonRequest(req);
  if (!body || !body.email || !body.password) {
    return jsonResponse({ success: false, message: "Invalid input" }, 400);
  }
  // If the email is not a valid email, return 400
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    return jsonResponse({ success: false, message: "Invalid email" }, 400);
  }
  const { email, password } = body;
  if (users.has(email)) {
    return jsonResponse({ success: false, message: "User already exists" }, 400);
  }

  users.set(email, await hashPassword(password));

  const token = generateJWT(email);
  return jsonResponse({ success: true, token });
}

// POST /login
async function handleLogin(req) {
  const body = await parseJsonRequest(req);
  if (!body || !body.email || !body.password) {
    return jsonResponse({ success: false, message: "Invalid input" }, 400);
  }
  // If the email is not a valid email, return 400
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    return jsonResponse({ success: false, message: "Invalid email" }, 400);
  }
  const { email, password } = body;
  if (!users.has(email)) {
    return jsonResponse({ success: false, message: "Invalid credentials" }, 401);
  }

  const storedHash = users.get(email);
  const providedHash = await hashPassword(password);

  if (storedHash !== providedHash) {
    return jsonResponse({ success: false, message: "Invalid credentials" }, 401);
  }

  const token = generateJWT(email);
  return jsonResponse({ success: true, token });
}

// DELETE /delete
// Reads the JWT from the Authorization header, extracts `email`, and deletes that user
async function handleDelete(req) {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) {
    return jsonResponse({ error: "Missing Authorization header." }, 401);
  }

  const parts = authHeader.split(" ");
  if (parts[0] !== "Bearer" || !parts[1]) {
    return jsonResponse({ error: "Malformed Authorization header." }, 401);
  }

  const token = parts[1];
  const payload = verifyJWT(token);
  if (!payload || !payload.email) {
    return jsonResponse({ error: "Invalid or expired token." }, 401);
  }

  // Attempt to delete user
  const email = payload.email;
  if (!users.has(email)) {
    return jsonResponse({ success: false, error: "User not found." }, 400);
  }

  users.delete(email);
  return jsonResponse({ success: true });
}

/* ------------------------------------------
 * Server
 * ------------------------------------------ */

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

    // Handle endpoints by method + path
    if (req.method === "POST") {
      switch (url.pathname) {
        case "/register":
          return handleRegister(req);
        case "/login":
          return handleLogin(req);
        default:
          return jsonResponse({ success: false, message: "Not Found" }, 404);
      }
    } else if (req.method === "DELETE" && url.pathname === "/delete") {
      return handleDelete(req);
    }

    return jsonResponse({ success: false, message: "Not Found" }, 404);
  },
});
