"""
Minimal Authentication Microservice in Python
------------------------------------------
Endpoints:
  1) POST /register
  2) POST /login
  3) DELETE /delete

Uses only standard library modules for maximum performance.
Stores users in-memory, returns JWT tokens, and uses HMAC-SHA256 for password hashing.
"""

import json
import hmac
import base64
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from typing import Dict, Optional, Tuple
import time

# Configuration
PORT = 3000
SECRET_KEY = b'YOUR_SUPER_SECRET'  # Convert to bytes for HMAC
users: Dict[str, str] = {}  # In-memory user store: {email: hashed_password}

def hash_password(password: str) -> str:
    """Hash a password using HMAC-SHA256."""
    return hmac.new(SECRET_KEY, password.encode(), hashlib.sha256).hexdigest()

def base64url_encode(data: bytes) -> str:
    """Create a base64 URL-safe string."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def generate_jwt(payload: dict) -> str:
    """Generate a JWT token using HS256 algorithm."""
    header = {'alg': 'HS256', 'typ': 'JWT'}
    
    # Encode header and payload
    header_encoded = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    
    # Create signature
    signature_input = f"{header_encoded}.{payload_encoded}".encode()
    signature = base64url_encode(
        hmac.new(SECRET_KEY, signature_input, hashlib.sha256).digest()
    )
    
    return f"{header_encoded}.{payload_encoded}.{signature}"

def verify_jwt(token: str) -> Optional[dict]:
    """Verify a JWT token and return the payload if valid."""
    try:
        header_encoded, payload_encoded, signature = token.split('.')
        
        # Verify signature
        signature_input = f"{header_encoded}.{payload_encoded}".encode()
        expected_signature = base64url_encode(
            hmac.new(SECRET_KEY, signature_input, hashlib.sha256).digest()
        )
        
        if signature != expected_signature:
            return None
            
        # Decode payload
        padding = '=' * (-len(payload_encoded) % 4)
        payload_json = base64.urlsafe_b64decode(payload_encoded + padding)
        return json.loads(payload_json)
    except Exception:
        return None

class AuthHandler(BaseHTTPRequestHandler):
    def send_json_response(self, status_code: int, data: dict) -> None:
        """Send a JSON response with given status code and data."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def read_json_body(self) -> Tuple[bool, Optional[dict]]:
        """Read and parse JSON body from request."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            return True, json.loads(body)
        except Exception:
            return False, None

    def do_POST(self) -> None:
        """Handle POST requests for /register and /login endpoints."""
        path = urlparse(self.path).path
        
        if path not in ['/register', '/login']:
            self.send_json_response(404, {'error': 'Not found'})
            return
            
        success, data = self.read_json_body()
        if not success or not data or 'email' not in data or 'password' not in data:
            self.send_json_response(400, {'error': 'Invalid JSON or missing fields.'})
            return
            
        email, password = data['email'], data['password']
        
        if path == '/register':
            if email in users:
                self.send_json_response(400, {'error': 'User already exists.'})
                return
                
            users[email] = hash_password(password)
            token = generate_jwt({'email': email})
            self.send_json_response(200, {'token': token})
            
        elif path == '/login':
            stored_hash = users.get(email)
            if not stored_hash or stored_hash != hash_password(password):
                self.send_json_response(401, {'error': 'Invalid credentials.'})
                return
                
            token = generate_jwt({'email': email})
            self.send_json_response(200, {'token': token})

    def do_DELETE(self) -> None:
        """Handle DELETE requests for /delete endpoint."""
        if self.path != '/delete':
            self.send_json_response(404, {'error': 'Not found'})
            return
            
        # Verify Authorization header
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            self.send_json_response(401, {'error': 'Missing Authorization header.'})
            return
            
        parts = auth_header.split()
        if len(parts) != 2 or parts[0] != 'Bearer':
            self.send_json_response(401, {'error': 'Malformed Authorization header.'})
            return
            
        token = parts[1]
        payload = verify_jwt(token)
        if not payload or 'email' not in payload:
            self.send_json_response(401, {'error': 'Invalid or expired token.'})
            return
            
        # Attempt to delete user
        email = payload['email']
        if email in users:
            del users[email]
            self.send_json_response(200, {'success': True})
        else:
            self.send_json_response(400, {'success': False, 'error': 'User not found.'})

def run_server():
    """Start the HTTP server."""
    server = HTTPServer(('localhost', PORT), AuthHandler)
    print(f'Server running on port {PORT}')
    server.serve_forever()

if __name__ == '__main__':
    run_server()
