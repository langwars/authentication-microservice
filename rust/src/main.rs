use hyper::{
    body::to_bytes,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Mutex};

use once_cell::sync::Lazy;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

type HmacSha256 = Hmac<Sha256>;

// ------------------------
// GLOBALS
// ------------------------

static USERS: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));
// This is your HMAC signing key (keep it secret).
static JWT_SECRET: &[u8] = b"my-very-secret-key-change-me";

// ------------------------
// DATA MODELS
// ------------------------

#[derive(Deserialize)]
struct AuthPayload {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct JwtResponse {
    token: String,
}

// ------------------------
// UTILITY FUNCTIONS
// ------------------------

fn json_response(status: StatusCode, body: Value) -> Response<Body> {
    let response_body = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(response_body))
        .unwrap()
}

/// A super-simplistic "hash" of the password.  
/// For real-world usage, switch to something like Argon2, PBKDF2, or bcrypt/scrypt.
fn hash_password(password: &str) -> String {
    // e.g., SHA256 or similar
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hashed = format!("{:x}", result);
    hashed
}

/// Create a minimal JWT with an HMAC-SHA256 signature.
/// Claims (payload) here only contain `email` and a naive "exp" (60 seconds).
fn create_jwt(email: &str) -> String {
    // Header
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });
    let header_encoded = base64_url_encode(serde_json::to_string(&header).unwrap().as_bytes());

    // Payload
    // For demonstration, we set an “exp” field = current_time + 60 (this is naive).
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let payload = json!({
        "email": email,
        "exp": exp
    });
    let payload_encoded = base64_url_encode(serde_json::to_string(&payload).unwrap().as_bytes());

    // Signature
    let signature = sign_hmac(format!("{}.{}", header_encoded, payload_encoded).as_bytes());
    let signature_encoded = base64_url_encode(&signature);

    // Final token
    format!("{}.{}.{}", header_encoded, payload_encoded, signature_encoded)
}

/// Verify a JWT token and return the email claim if valid; otherwise None.
fn verify_jwt(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_encoded = parts[0];
    let payload_encoded = parts[1];
    let signature_encoded = parts[2];

    // Recompute signature
    let recomputed_signature =
        sign_hmac(format!("{}.{}", header_encoded, payload_encoded).as_bytes());

    // Compare signatures in constant time
    let signature = base64_url_decode(signature_encoded)?;
    if !constant_time_eq(&signature, &recomputed_signature) {
        return None;
    }

    // Decode payload
    let payload_json = base64_url_decode(payload_encoded)?;
    let payload: Value = serde_json::from_slice(&payload_json).ok()?;
    let email = payload.get("email")?.as_str()?.to_string();
    let exp = payload.get("exp")?.as_u64()?;

    // Check expiration
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if now > exp {
        return None;
    }

    Some(email)
}

/// Compute HMAC-SHA256 of a message using our secret.
fn sign_hmac(data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(JWT_SECRET)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// A constant-time comparison helper.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b) {
        result |= x ^ y;
    }
    result == 0
}

/// Base64 URL-safe (no padding) encode
fn base64_url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64 URL-safe (no padding) decode
fn base64_url_decode(data: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(data).ok()
}

// ------------------------
// HANDLERS
// ------------------------

async fn handle_register(req: Request<Body>) -> Response<Body> {
    // Parse body
    let whole_body = to_bytes(req.into_body()).await.unwrap_or_default();
    let payload = match serde_json::from_slice::<AuthPayload>(&whole_body) {
        Ok(p) => p,
        Err(_) => {
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Invalid JSON"}));
        }
    };

    // Very naive check for existence
    let mut users = USERS.lock().unwrap();
    if users.contains_key(&payload.email) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "User already exists"}),
        );
    }

    let hashed_password = hash_password(&payload.password);
    users.insert(payload.email.clone(), hashed_password);

    // Issue a JWT
    let token = create_jwt(&payload.email);
    let resp = JwtResponse { token };
    return json_response(StatusCode::OK, json!(resp));
}

async fn handle_login(req: Request<Body>) -> Response<Body> {
    // Parse body
    let whole_body = to_bytes(req.into_body()).await.unwrap_or_default();
    let payload = match serde_json::from_slice::<AuthPayload>(&whole_body) {
        Ok(p) => p,
        Err(_) => {
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Invalid JSON"}));
        }
    };

    // Check user
    let users = USERS.lock().unwrap();
    if let Some(stored_hash) = users.get(&payload.email) {
        let hashed_password = hash_password(&payload.password);
        if &hashed_password == stored_hash {
            // Issue a JWT
            let token = create_jwt(&payload.email);
            let resp = JwtResponse { token };
            return json_response(StatusCode::OK, json!(resp));
        }
    }

    json_response(
        StatusCode::UNAUTHORIZED,
        json!({"error": "Invalid credentials"}),
    )
}

async fn handle_delete(req: Request<Body>) -> Response<Body> {
    // Check HTTP method
    if req.method() != Method::DELETE {
        return json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error": "Method not allowed"}),
        );
    }

    // Check Authorization header
    let auth_header = match req.headers().get("authorization") {
        Some(h) => h.to_str().unwrap_or_default(),
        None => {
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Missing Authorization header"}),
            );
        }
    };
    let parts: Vec<&str> = auth_header.split_whitespace().collect();
    if parts.len() != 2 || parts[0] != "Bearer" {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Malformed Authorization header"}),
        );
    }
    let token = parts[1];

    // Verify JWT
    let email = match verify_jwt(token) {
        Some(e) => e,
        None => {
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Invalid or expired token"}),
            );
        }
    };

    // Attempt to delete user
    let mut users = USERS.lock().unwrap();
    if users.remove(&email).is_some() {
        return json_response(StatusCode::OK, json!({"success": true}));
    } else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"success": false, "error": "User not found"}),
        );
    }
}

// ------------------------
// ROUTER
// ------------------------

async fn router(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();

    match (req.method(), path.as_str()) {
        (&Method::POST, "/register") => Ok(handle_register(req).await),
        (&Method::POST, "/login") => Ok(handle_login(req).await),
        // For delete, we specifically expect DELETE /delete
        (&Method::DELETE, "/delete") => Ok(handle_delete(req).await),
        _ => Ok(json_response(StatusCode::NOT_FOUND, json!({"error": "Not Found"}))),
    }
}

// ------------------------
// MAIN
// ------------------------

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(router))
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Server running on {}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
