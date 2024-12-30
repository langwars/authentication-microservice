<?php
/**
 * Minimal Authentication Microservice in PHP
 * ----------------------------------------------
 * Endpoints:
 *   1) POST /register
 *   2) POST /login
 *   3) DELETE /delete
 *
 * Stores users in-memory as { email: hashedPassword }.
 * Returns a JWT on successful register/login, which includes the user email.
 * Verifies the JWT before allowing /delete.
 * Uses native PHP functions for optimal performance.
 */

declare(strict_types=1);

// -------------------------------------------------------------------------
// Configuration & Storage
// -------------------------------------------------------------------------
const SECRET_KEY = 'YOUR_SUPER_SECRET';    // Secret key for HMAC signing
$users = [];                               // In-memory user store

// -------------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------------

/**
 * Send a JSON response with a given status code and object data.
 */
function sendJSON(int $statusCode, array $data): void {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

/**
 * Hash a password using HMAC-SHA256 with SECRET_KEY.
 */
function hashPassword(string $password): string {
    return hash_hmac('sha256', $password, SECRET_KEY);
}

/**
 * Create a base64 URL-safe string.
 */
function base64UrlEncode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Generate a JWT with the HS256 algorithm (HMAC-SHA256).
 */
function generateJWT(array $payload): string {
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    
    $encodedHeader = base64UrlEncode(json_encode($header));
    $encodedPayload = base64UrlEncode(json_encode($payload));
    
    $signatureData = "$encodedHeader.$encodedPayload";
    $signature = base64UrlEncode(
        hash_hmac('sha256', $signatureData, SECRET_KEY, true)
    );
    
    return "$encodedHeader.$encodedPayload.$signature";
}

/**
 * Verify a JWT and return the decoded payload if valid, or null if invalid.
 */
function verifyJWT(?string $token): ?array {
    if (!$token) return null;
    
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    
    [$encodedHeader, $encodedPayload, $signature] = $parts;
    $signatureData = "$encodedHeader.$encodedPayload";
    
    // Recompute signature
    $expectedSignature = base64UrlEncode(
        hash_hmac('sha256', $signatureData, SECRET_KEY, true)
    );
    
    // Compare signatures
    if (!hash_equals($signature, $expectedSignature)) return null;
    
    // Decode payload
    try {
        return json_decode(
            base64_decode(strtr($encodedPayload, '-_', '+/')),
            true
        );
    } catch (Exception $e) {
        return null;
    }
}

/**
 * Get JSON request body
 */
function getJSONBody(): ?array {
    $rawBody = file_get_contents('php://input');
    return json_decode($rawBody, true);
}

// -------------------------------------------------------------------------
// Request Handlers
// -------------------------------------------------------------------------

function handleRegister(): void {
    global $users;
    
    $data = getJSONBody();
    if (!$data || !isset($data['email']) || !isset($data['password'])) {
        sendJSON(400, ['error' => 'Invalid JSON or missing fields.']);
    }
    
    $email = $data['email'];
    $password = $data['password'];
    
    if (isset($users[$email])) {
        sendJSON(400, ['error' => 'User already exists.']);
    }
    
    // Hash and store password
    $users[$email] = hashPassword($password);
    
    // Return JWT
    $token = generateJWT(['email' => $email]);
    sendJSON(200, ['token' => $token]);
}

function handleLogin(): void {
    global $users;
    
    $data = getJSONBody();
    if (!$data || !isset($data['email']) || !isset($data['password'])) {
        sendJSON(400, ['error' => 'Invalid JSON or missing fields.']);
    }
    
    $email = $data['email'];
    $password = $data['password'];
    
    if (!isset($users[$email])) {
        sendJSON(401, ['error' => 'Invalid credentials.']);
    }
    
    $givenHashed = hashPassword($password);
    if (!hash_equals($users[$email], $givenHashed)) {
        sendJSON(401, ['error' => 'Invalid credentials.']);
    }
    
    // Return JWT
    $token = generateJWT(['email' => $email]);
    sendJSON(200, ['token' => $token]);
}

function handleDelete(): void {
    global $users;
    
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? null;
    
    if (!$authHeader) {
        sendJSON(401, ['error' => 'Missing Authorization header.']);
    }
    
    $parts = explode(' ', $authHeader);
    if ($parts[0] !== 'Bearer' || !isset($parts[1])) {
        sendJSON(401, ['error' => 'Malformed Authorization header.']);
    }
    
    $token = $parts[1];
    $payload = verifyJWT($token);
    
    if (!$payload || !isset($payload['email'])) {
        sendJSON(401, ['error' => 'Invalid or expired token.']);
    }
    
    $email = $payload['email'];
    if (isset($users[$email])) {
        unset($users[$email]);
        sendJSON(200, ['success' => true]);
    } else {
        sendJSON(400, ['success' => false, 'error' => 'User not found.']);
    }
}

// -------------------------------------------------------------------------
// Main Router
// -------------------------------------------------------------------------

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// CORS headers for API
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($method === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Route requests
switch ("$method $uri") {
    case 'POST /register':
        handleRegister();
        break;
    case 'POST /login':
        handleLogin();
        break;
    case 'DELETE /delete':
        handleDelete();
        break;
    default:
        sendJSON(404, ['error' => 'Not Found']);
}
