import { serve } from "bun";
import { SignJWT, jwtVerify } from "jose";

// In-memory user store
const users = new Map();
const SECRET = "my-secret-key";
const secretKey = new TextEncoder().encode(SECRET);

// Generate JWT
async function generateJWT(email) {
  return await new SignJWT({ email })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .sign(secretKey);
}

// Verify JWT
async function verifyJWT(token) {
  try {
    const { payload } = await jwtVerify(token, secretKey);
    return payload;
  } catch {
    return null;
  }
}

// Hash password
function hashPassword(password) {
  return Bun.hash(password, { algorithm: "sha256", encoding: "base64" });
}

// Parse JSON
async function parseJsonRequest(req) {
  try {
    return await req.json();
  } catch {
    return null;
  }
}

// JSON response
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// POST /register
async function handleRegister(req) {
  const body = await parseJsonRequest(req);
  if (!body || !body.email || !body.password) {
    return jsonResponse({ success: false, message: "Invalid input" }, 400);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    return jsonResponse({ success: false, message: "Invalid email" }, 400);
  }
  const { email, password } = body;
  if (users.has(email)) {
    return jsonResponse({ success: false, message: "User already exists" }, 400);
  }
  users.set(email, await hashPassword(password));
  const token = await generateJWT(email);
  return jsonResponse({ success: true, token });
}

// POST /login
async function handleLogin(req) {
  const body = await parseJsonRequest(req);
  if (!body || !body.email || !body.password) {
    return jsonResponse({ success: false, message: "Invalid input" }, 400);
  }
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
  const token = await generateJWT(email);
  return jsonResponse({ success: true, token });
}

// DELETE /delete
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
  const payload = await verifyJWT(token);
  if (!payload || !payload.email) {
    return jsonResponse({ error: "Invalid or expired token." }, 401);
  }
  const email = payload.email;
  if (!users.has(email)) {
    return jsonResponse({ success: false, error: "User not found." }, 400);
  }
  users.delete(email);
  return jsonResponse({ success: true });
}

// Server
serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);
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
