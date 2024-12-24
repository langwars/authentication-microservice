package auth_service

import "core:net"
import "core:crypto/sha2"
import "core:encoding/json"
import "core:strings"
import "core:bytes"
import "core:time"
import "core:encoding/base64"
import "core:fmt"
import "core:os"

User :: struct {
    email: string,
    password_hash: [32]byte,
}

JWT_Header :: struct {
    alg: string,
    typ: string,
}

JWT_Payload :: struct {
    email: string,
    exp: i64,
}

// In-memory user storage
users: map[string]User
JWT_SECRET := "your-secret-key-here"

init_users :: proc() {
    users = make(map[string]User)
}

hash_password :: proc(password: string) -> [32]byte {
    data := transmute([]byte)password
    hash: [32]byte
    ctx: sha2.Context_256
    sha2.init_256(&ctx)
    sha2.write(&ctx, data)
    sha2.sum_256(&ctx, hash[:])
    return hash
}

create_jwt :: proc(email: string) -> string {
    header := JWT_Header{alg = "HS256", typ = "JWT"}
    payload := JWT_Payload{
        email = email,
        exp = time.time_to_unix(time.now()) + 3600,
    }

    header_json, _ := json.marshal(header)
    payload_json, _ := json.marshal(payload)

    header_b64 := base64.encode(header_json[:])
    payload_b64 := base64.encode(payload_json[:])

    message := strings.concatenate({header_b64, ".", payload_b64})
    
    signature: [32]byte
    ctx: sha2.Context_256
    sha2.init_256(&ctx)
    sha2.write(&ctx, transmute([]byte)strings.concatenate({message, JWT_SECRET}))
    sha2.sum_256(&ctx, signature[:])
    signature_b64 := base64.encode(signature[:])

    return strings.concatenate({message, ".", signature_b64})
}

verify_jwt :: proc(token: string) -> (JWT_Payload, bool) {
    parts := strings.split(token, ".")
    if len(parts) != 3 {
        return JWT_Payload{}, false
    }

    message := strings.concatenate({parts[0], ".", parts[1]})
    
    expected_sig: [32]byte
    ctx: sha2.Context_256
    sha2.init_256(&ctx)
    sha2.write(&ctx, transmute([]byte)strings.concatenate({message, JWT_SECRET}))
    sha2.sum_256(&ctx, expected_sig[:])
    expected_sig_b64 := base64.encode(expected_sig[:])

    if parts[2] != expected_sig_b64 {
        return JWT_Payload{}, false
    }

    payload_json, decode_err := base64.decode(parts[1])
    if decode_err != nil {
        return JWT_Payload{}, false
    }

    payload: JWT_Payload
    json.unmarshal(payload_json, &payload)

    if payload.exp < time.time_to_unix(time.now()) {
        return JWT_Payload{}, false
    }

    return payload, true
}

create_response :: proc(status: int, body: any) -> string {
    json_body, _ := json.marshal(body)
    response := fmt.tprintf("HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
        status, len(json_body), string(json_body))
    return response
}

handle_request :: proc(socket: net.TCP_Socket) {
    buffer: [4096]byte
    bytes_read, err := net.recv_tcp(socket, buffer[:])
    if err != nil || bytes_read <= 0 {
        return
    }

    request := string(buffer[:bytes_read])
    lines := strings.split(request, "\r\n")
    if len(lines) < 1 {
        return
    }

    first_line := strings.split(lines[0], " ")
    if len(first_line) != 3 {
        return
    }

    method := first_line[0]
    path := first_line[1]

    // Parse headers
    headers := make(map[string]string)
    header_end := 0
    for i := 1; i < len(lines); i += 1 {
        if lines[i] == "" {
            header_end = i
            break
        }
        header_parts := strings.split(lines[i], ": ")
        if len(header_parts) == 2 {
            headers[header_parts[0]] = header_parts[1]
        }
    }

    // Parse body
    body := strings.join(lines[header_end+1:], "\r\n")

    response: string
    switch path {
    case "/register":
        if method != "POST" {
            response = create_response(405, map[string]string{"error" = "Method not allowed"})
            break
        }

        data: struct {
            email: string,
            password: string,
        }
        if json.unmarshal(transmute([]byte)body, &data) != nil {
            response = create_response(400, map[string]string{"error" = "Invalid JSON"})
            break
        }

        if data.email in users {
            response = create_response(400, map[string]string{"error" = "User already exists"})
            break
        }

        users[data.email] = User{
            email = data.email,
            password_hash = hash_password(data.password),
        }

        token := create_jwt(data.email)
        response = create_response(200, map[string]string{"token" = token})

    case "/login":
        if method != "POST" {
            response = create_response(405, map[string]string{"error" = "Method not allowed"})
            break
        }

        data: struct {
            email: string,
            password: string,
        }
        if json.unmarshal(transmute([]byte)body, &data) != nil {
            response = create_response(400, map[string]string{"error" = "Invalid JSON"})
            break
        }

        user, exists := users[data.email]
        if !exists || hash_password(data.password) != user.password_hash {
            response = create_response(401, map[string]string{"error" = "Invalid credentials"})
            break
        }

        token := create_jwt(data.email)
        response = create_response(200, map[string]string{"token" = token})

    case "/delete":
        if method != "DELETE" {
            response = create_response(405, map[string]string{"error" = "Method not allowed"})
            break
        }

        auth_header, has_auth := headers["Authorization"]
        if !has_auth {
            response = create_response(401, map[string]string{"error" = "Missing Authorization header"})
            break
        }

        parts := strings.split(auth_header, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            response = create_response(401, map[string]string{"error" = "Malformed Authorization header"})
            break
        }

        payload, valid := verify_jwt(parts[1])
        if !valid {
            response = create_response(401, map[string]string{"error" = "Invalid or expired token"})
            break
        }

        if _, exists := users[payload.email]; exists {
            delete_key(&users, payload.email)
            response = create_response(200, map[string]bool{"success" = true})
        } else {
            response = create_response(400, map[string]any{"success" = false, "error" = "User not found"})
        }

    case:
        response = create_response(404, map[string]string{"error" = "Not found"})
    }

    net.send_tcp(socket, transmute([]byte)response)
    net.close(socket)
}

main :: proc() {
    init_users()

    socket, err := net.listen_tcp(net.Endpoint{
        address = net.IP4_Loopback,
        port = 3000,
    })
    if err != nil {
        fmt.eprintln("Failed to create and bind socket:", err)
        os.exit(1)
    }
    defer net.close(socket)

    fmt.println("Server running on http://localhost:3000")

    for {
        client, _, err := net.accept_tcp(socket)
        if err != nil {
            continue
        }
        handle_request(client)
    }
}
