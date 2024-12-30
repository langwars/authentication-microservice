package main

import core:fmt
import core:os
import core:strings
import core:net
import core:json
import crypto:hmac
import crypto:sha256
import encoding:base64

// -----------------------------------------------------------------------------
// Configuration & State
// -----------------------------------------------------------------------------

// Simple static secret for signing tokens (DON'T do this in production)
TOKEN_SECRET: string :: "REPLACE_ME_WITH_BETTER_SECRET";

// We store users in memory as a map of email -> hashed_password
users: map[string]string;

// -----------------------------------------------------------------------------
// Helper Utilities
// -----------------------------------------------------------------------------

// JSON response helper
// Returns a basic HTTP response with a JSON payload
send_json_response :: proc(conn: ^net.TCP_Conn, code: int, body: string) {
    // Minimal HTTP response with a JSON body
    // For benchmarking, keep headers small
    response := strings.concat(
        "HTTP/1.1 ", fmt.itoa(code), " OK\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", fmt.itoa(body.len), "\r\n",
        "Connection: close\r\n",
        "\r\n",
        body
    );
    _ = conn.write_string(response);
}

// Creates a minimal JSON string from a map of string->string 
// (Just for quick usage; you might want a more robust approach)
make_json_object :: proc(kvs: []struct{name, value: string}) -> string {
    // e.g. [{name="error",value="Missing field"}]
    // -> {"error":"Missing field"}
    parts := []string{};
    for kv in kvs {
        part := strings.concat("\"", kv.name, "\":\"", kv.value, "\"");
        parts = append(parts, part);
    }
    return strings.concat("{", strings.join(parts, ","), "}");
}

// Minimal password hashing (SHA-256)
hash_password :: proc(password: string) -> string {
    hashed := sha256.sum(password);
    // Convert raw bytes to hex string (64 hex chars for 256 bits)
    return fmt.hex_bytes(hashed);
}

// Checks if the provided password, when hashed, matches `expected`
check_password :: proc(password, expected: string) -> bool {
    return hash_password(password) == expected;
}

// -----------------------------------------------------------------------------
// JWT Helpers (HS256)
// -----------------------------------------------------------------------------

// Minimal base64-url encode (just raw base64, then fix chars)
// Enough for a naive HS256 JWT
base64url_encode :: proc(data: string) -> string {
    raw_b64 := base64.encode(data);
    // JWT needs URL-safe encoding; minimal approach
    // Replace + with -, / with _, strip trailing =
    raw_b64 = strings.replace(raw_b64, "+", "-");
    raw_b64 = strings.replace(raw_b64, "/", "_");
    raw_b64 = strings.replace(raw_b64, "=", "");
    return raw_b64;
}

// Minimal base64-url decode (inverse of above)
base64url_decode :: proc(encoded: string) -> string {
    // revert - -> +, _ -> /
    encoded = strings.replace(encoded, "-", "+");
    encoded = strings.replace(encoded, "_", "/");
    // pad with '=' to multiple of 4
    needed := 4 - (encoded.len % 4);
    if needed != 4 {
        encoded = strings.concat(encoded, strings.repeat("=", needed));
    }
    decoded := base64.decode(encoded);
    return decoded;
}

// Create a JWT for user with a single claim: `email`
generate_jwt :: proc(email: string) -> string {
    // Minimal HS256 JWT
    // Header: {"alg":"HS256","typ":"JWT"}
    let header_str   = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    let payload_str  = strings.concat("{\"email\":\"", email, "\"}");

    let header_b64   = base64url_encode(header_str);
    let payload_b64  = base64url_encode(payload_str);

    let signature_input = strings.concat(header_b64, ".", payload_b64);
    let signature_hmac  = hmac.sum(sha256, signature_input, TOKEN_SECRET);
    let signature_b64   = base64url_encode(signature_hmac);

    return strings.concat(header_b64, ".", payload_b64, ".", signature_b64);
}

// Verify the JWT signature and parse out the `email` from the payload.
// Returns the `email` if valid; otherwise returns an empty string.
verify_jwt :: proc(token: string) -> string {
    parts := strings.split(token, ".");
    if parts.count != 3 {
        return ""; // malformed
    }
    let header_b64   = parts[0];
    let payload_b64  = parts[1];
    let signature_b64= parts[2];

    let signature_input = strings.concat(header_b64, ".", payload_b64);
    let expected_sig = hmac.sum(sha256, signature_input, TOKEN_SECRET);
    let expected_sig_b64 = base64url_encode(expected_sig);
    if signature_b64 != expected_sig_b64 {
        return ""; // signature mismatch
    }

    // decode payload
    let payload_json  = base64url_decode(payload_b64);
    // Try to parse the `email` manually or with JSON
    // We'll do a minimal parse looking for: "email":"some@thing"
    // In production, you'd parse the JSON properly
    email_marker := "\"email\":\"";
    start_idx := strings.index(payload_json, email_marker);
    if start_idx < 0 {
        return "";
    }
    start_idx += email_marker.len;
    end_idx := strings.index_from(payload_json, "\"", start_idx);
    if end_idx < 0 {
        return "";
    }
    return payload_json[start_idx..end_idx];
}

// -----------------------------------------------------------------------------
// Request Parsing
// -----------------------------------------------------------------------------

// Minimal function to parse the first line of the HTTP request
// Returns (method, path)
parse_request_line :: proc(line: string) -> (string, string) {
    parts := strings.split(line, " ");
    if parts.count < 2 {
        return ("", "");
    }
    return (parts[0], parts[1]);
}

// Read the entire HTTP request text from the connection
// (Be careful: real code needs timeouts, content-length checks, etc.)
read_http_request :: proc(conn: ^net.TCP_Conn) -> string {
    // Just read in a loop
    // If the load is big, you might want a more robust approach
    buf := make([]u8, 2048);
    total_data := "";
    for {
        n_read, err := conn.read(buf);
        if err != nil || n_read <= 0 {
            break;
        }
        total_data += strings.from_bytes(buf[0..n_read]);
        // Very naive assumption: stop if we've read a full request 
        // (or if there's no Content-Length). 
        // For a micro-benchmark, this might suffice.
        // In real apps, parse Content-Length or chunked encoding.
        if n_read < buf.count {
            break;
        }
    }
    return total_data;
}

// -----------------------------------------------------------------------------
// Route Handlers
// -----------------------------------------------------------------------------

// Endpoint: POST /register
// Body: { "email":"...", "password":"..." }
// If the user does not exist, create user, return JWT. If user already exists, error.
handle_register :: proc(conn: ^net.TCP_Conn, body: string) {
    // We do a quick parse for email & password
    email := extract_json_field(body, "email");
    pass  := extract_json_field(body, "password");
    if email.len == 0 or pass.len == 0 {
        let error_json = make_json_object([{name="error", value="Missing email or password"}]);
        send_json_response(conn, 400, error_json);
        return;
    }

    if users[email] != "" {
        let error_json = make_json_object([{name="error", value="User already exists"}]);
        send_json_response(conn, 400, error_json);
        return;
    }

    // Hash password
    hashed_password := hash_password(pass);
    users[email] = hashed_password;

    // Return a JWT
    token := generate_jwt(email);
    let response_body = make_json_object([{name="token", value=token}]);
    send_json_response(conn, 200, response_body);
}

// Endpoint: POST /login
// Body: { "email":"...", "password":"..." }
// If user exists & password correct, return JWT; else error
handle_login :: proc(conn: ^net.TCP_Conn, body: string) {
    email := extract_json_field(body, "email");
    pass  := extract_json_field(body, "password");
    if email.len == 0 or pass.len == 0 {
        let error_json = make_json_object([{name="error", value="Missing email or password"}]);
        send_json_response(conn, 400, error_json);
        return;
    }

    stored_hash := users[email];
    if stored_hash.len == 0 {
        // user not found
        let error_json = make_json_object([{name="error", value="User not found"}]);
        send_json_response(conn, 400, error_json);
        return;
    }

    if not check_password(pass, stored_hash) {
        let error_json = make_json_object([{name="error", value="Invalid password"}]);
        send_json_response(conn, 401, error_json);
        return;
    }

    // Return a JWT
    token := generate_jwt(email);
    let response_body = make_json_object([{name="token", value=token}]);
    send_json_response(conn, 200, response_body);
}

// Endpoint: DELETE /delete
// Expects a JWT in the Authorization header "Bearer <jwt>"
handle_delete :: proc(conn: ^net.TCP_Conn, headers: string) {
    // Minimal parse for "Authorization: Bearer X"
    authMarker := "Authorization: Bearer ";
    idx := strings.index(headers, authMarker);
    if idx < 0 {
        let resp = make_json_object([{name="error", value="Missing Authorization header"}]);
        send_json_response(conn, 401, resp);
        return;
    }

    idx += authMarker.len;
    // Grab remainder of line
    endOfLine := strings.index_from(headers, "\r\n", idx);
    if endOfLine < 0 {
        endOfLine = headers.len;
    }

    token := headers[idx..endOfLine];
    email := verify_jwt(token);
    if email.len == 0 {
        let resp = make_json_object([{name="error", value="Invalid or expired token"}]);
        send_json_response(conn, 401, resp);
        return;
    }

    // Attempt to delete user
    stored := users[email];
    if stored.len != 0 {
        map_remove(&users, email);
        let success_json = make_json_object([{name="success", value="true"}]);
        send_json_response(conn, 200, success_json);
    } else {
        let fail_json = make_json_object([
            {name="success", value="false"},
            {name="error",   value="User not found"}
        ]);
        send_json_response(conn, 400, fail_json);
    }
}

// Utility: extract_json_field
// Very naive "finder" for `"field":"value"` in a JSON string
extract_json_field :: proc(json_text: string, field: string) -> string {
    // e.g. field="email" => looking for: `"email":"SOMETHING"`
    pattern := strings.concat("\"", field, "\":\"");
    start_idx := strings.index(json_text, pattern);
    if start_idx < 0 {
        return "";
    }
    start_idx += pattern.len;
    end_idx := strings.index_from(json_text, "\"", start_idx);
    if end_idx < 0 {
        return "";
    }
    return json_text[start_idx..end_idx];
}

// -----------------------------------------------------------------------------
// Main / HTTP Server
// -----------------------------------------------------------------------------

main :: proc() {
    // Initialize the in-memory map
    map_init(&users, .{});

    // Ideally store your secret in env or config
    // or generate a random secret at runtime, etc.
    // For demo/benchmark, we'll keep it here:
    TOKEN_SECRET = "SUPER_SECRET_CHANGE_ME";

    // Start a TCP listener
    address := net.Addr{
        ip   = net.ipv4(127, 0, 0, 1),
        port = 8080,
    };
    listener, err := net.listen_tcp(address);
    if err != nil {
        fmt.println("Failed to bind: ", err);
        return;
    }
    defer listener.close();

    fmt.println("Listening on 127.0.0.1:8080 ...");

    // For a higher-throughput server, you'd spawn worker threads, use concurrency, etc.
    // Here we do a simple loop to handle one connection at a time.
    for {
        conn, err := listener.accept();
        if err != nil {
            fmt.println("Accept error:", err);
            continue;
        }
        handle_connection(^conn);
        conn.close(); 
    }
}

// Handle a single connection
handle_connection :: proc(conn: ^net.TCP_Conn) {
    request := read_http_request(conn);
    if request.len == 0 {
        return;
    }

    // Split off request-line from headers+body
    // Request line: e.g. "POST /login HTTP/1.1"
    line_end := strings.index(request, "\r\n");
    if line_end < 0 {
        return;
    }
    let request_line  = request[0..line_end];
    let remainder     = request[line_end+2..]; // skip \r\n

    let (method, path) = parse_request_line(request_line);

    // For simplicity, everything after the first line is "headers+body"
    // We'll do naive substring ops. 
    // (In real code, you'd parse Content-Length or chunked encoding.)
    headers := remainder;
    body    := "";

    // Check for blank line separating headers from body
    blank_idx := strings.index(headers, "\r\n\r\n");
    if blank_idx >= 0 {
        body    = headers[blank_idx+4..];
        headers = headers[0..blank_idx];
    }

    // Route
    switch method {
    case "POST":
        switch path {
        case "/register":
            handle_register(conn, body);
        case "/login":
            handle_login(conn, body);
        default:
            let error_resp = make_json_object([{name="error", value="Unknown POST endpoint"}]);
            send_json_response(conn, 404, error_resp);
        }
    case "DELETE":
        switch path {
        case "/delete":
            handle_delete(conn, headers);
        default:
            let error_resp = make_json_object([{name="error", value="Unknown DELETE endpoint"}]);
            send_json_response(conn, 404, error_resp);
        }
    default:
        let error_resp = make_json_object([{name="error", value="Method Not Supported"}]);
        send_json_response(conn, 405, error_resp);
    }
}