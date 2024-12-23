// @ts-ignore
import { serve } from "https://deno.land/std@0.192.0/http/server.ts";

/**
 * In-memory user store: Map<email, hashedPassword>
 */
const users = new Map<string, string>();

/**
 * Shared secret key for JWT signing/verifying.
 * In real-world usage, store securely and rotate periodically.
 */
const JWT_SECRET = "MY_SUPER_SECRET_KEY";

const PORT = 3000;

/**
 * Helper: Base64URL-encode (for JWT header/payload/signature).
 * Replaces + with -, / with _, and removes trailing =
 */
function base64UrlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Helper: Base64URL-decode
 * Reverse of base64UrlEncode
 */
function base64UrlDecode(str: string): Uint8Array {
  // Replace URL-friendly chars
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  // Re-pad with '='
  while (str.length % 4 !== 0) {
    str += "=";
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Hash the password using SHA-256 (simple demo—use stronger approach in prod).
 */
async function hashPassword(password: string): Promise<string> {
  const data = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

/**
 * Create a JWT with HS256 signature, containing the user's email.
 * (Minimal example: no expiration, iat, etc.)
 */
async function createJWT(email: string): Promise<string> {
  // Header
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(header))
  );

  // Payload
  const payload = { email };
  const encodedPayload = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  // Sign: HMAC-SHA256 over "header.payload"
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const encodedSignature = base64UrlEncode(signature);

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Verify the token (HS256). Return payload on success, null on failure.
 */
async function verifyJWT(token: string): Promise<{ email: string } | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // Re-sign header+payload
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
  const newSignature = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const newEncodedSignature = base64UrlEncode(newSignature);

  // Compare signatures
  if (newEncodedSignature !== encodedSignature) {
    return null;
  }

  // Decode payload
  try {
    const payloadJson = new TextDecoder().decode(base64UrlDecode(encodedPayload));
    const payload = JSON.parse(payloadJson);
    return payload;
  } catch {
    return null;
  }
}

/**
 * Utility: Return a JSON Response
 */
function sendJSON(status: number, data: Record<string, unknown>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Handle Register Request */
async function handleRegister(req: Request): Promise<Response> {
  try {
    const { email, password } = await req.json();
    if (!email || !password) {
      return sendJSON(400, { error: "Missing email or password" });
    }

    if (users.has(email)) {
      return sendJSON(409, { error: "User already exists" });
    }

    // Hash and store
    const hashed = await hashPassword(password);
    users.set(email, hashed);

    // Return token
    const token = await createJWT(email);
    return sendJSON(200, { token });
  } catch {
    return sendJSON(400, { error: "Bad Request" });
  }
}

/** Handle Login Request */
async function handleLogin(req: Request): Promise<Response> {
  try {
    const { email, password } = await req.json();
    if (!email || !password) {
      return sendJSON(400, { error: "Missing email or password" });
    }

    const storedHash = users.get(email);
    if (!storedHash) {
      return sendJSON(404, { error: "User not found" });
    }

    const hashed = await hashPassword(password);
    if (hashed !== storedHash) {
      return sendJSON(401, { error: "Invalid credentials" });
    }

    // Return token
    const token = await createJWT(email);
    return sendJSON(200, { token });
  } catch {
    return sendJSON(400, { error: "Bad Request" });
  }
}

/** Handle Delete Request (requires Bearer token in Authorization header) */
async function handleDelete(req: Request): Promise<Response> {
  // Check Authorization header
  const authHeader = req.headers.get("authorization");
  if (!authHeader) {
    return sendJSON(401, { error: "Missing Authorization header." });
  }

  const parts = authHeader.split(" ");
  if (parts[0] !== "Bearer" || !parts[1]) {
    return sendJSON(401, { error: "Malformed Authorization header." });
  }

  const token = parts[1];
  const payload = await verifyJWT(token);
  if (!payload || !payload.email) {
    return sendJSON(401, { error: "Invalid or expired token." });
  }

  // Attempt to delete user
  if (users.has(payload.email)) {
    users.delete(payload.email);
    return sendJSON(200, { success: true });
  } else {
    return sendJSON(400, { success: false, error: "User not found." });
  }
}

/** Main Server Logic */
serve(async (req: Request) => {
  const url = new URL(req.url);

  if (url.pathname === "/register" && req.method === "POST") {
    return handleRegister(req);
  } else if (url.pathname === "/login" && req.method === "POST") {
    return handleLogin(req);
  } else if (url.pathname === "/delete" && req.method === "DELETE") {
    return handleDelete(req);
  }

  return sendJSON(404, { error: "Not Found" });
}, { port: PORT });
