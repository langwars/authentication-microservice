const std = @import("std");
const net = std.net;
const json = std.json;
const crypto = std.crypto;
const mem = std.mem;
const base64 = std.base64;
const Allocator = std.mem.Allocator;

const PORT = 3000;
const SECRET_KEY = "YOUR_SUPER_SECRET";

// Error set for request handling
pub const RequestError = error{
    InvalidRequest,
    InvalidPayload,
};

// -------------------- Data Structures -------------------- //

// A User in memory
const User = struct {
    email: []const u8,
    password_hash: [crypto.hash.sha2.Sha256.digest_length]u8,
};

// JWT header
const JwtHeader = struct {
    alg: []const u8,
    typ: []const u8,

    // Minimal toJson method so std.json can serialize it
    pub fn toJson(self: @This(), comptime options: std.json.StringifyOptions) !void {
        try options.writer.writeByte('{');
        var sep = false;

        inline for (@typeInfo(@This()).Struct.fields) |f| {
            if (sep) {
                try options.writer.writeByte(',');
            } else {
                sep = true;
            }

            try options.writer.writeString("\"");
            try options.writer.writeString(f.name);
            try options.writer.writeString("\":");

            const val = @field(self, f.name);
            // We'll assume all fields are string slices
            try options.writer.writeString("\"");
            try options.writer.writeSlice(val);
            try options.writer.writeString("\"");
        }

        try options.writer.writeByte('}');
    }
};

// JWT payload
const JwtPayload = struct {
    email: []const u8,

    pub fn toJson(self: @This(), comptime options: std.json.StringifyOptions) !void {
        try options.writer.writeByte('{');
        var sep = false;

        inline for (@typeInfo(@This()).Struct.fields) |f| {
            if (sep) {
                try options.writer.writeByte(',');
            } else {
                sep = true;
            }

            try options.writer.writeString("\"");
            try options.writer.writeString(f.name);
            try options.writer.writeString("\":");

            const val = @field(self, f.name);
            try options.writer.writeString("\"");
            try options.writer.writeSlice(val);
            try options.writer.writeString("\"");
        }

        try options.writer.writeByte('}');
    }
};

// Instead of field name `error:`, we rename it to `err_msg:`
const ErrorResponse = struct {
    err_msg: []const u8,

    pub fn toJson(self: @This(), comptime options: std.json.StringifyOptions) !void {
        try options.writer.writeByte('{');
        // We *still* output "error" as the JSON key:
        try options.writer.writeString("\"error\":\"");
        try options.writer.writeSlice(self.err_msg);
        try options.writer.writeString("\"}");
    }
};

const TokenResponse = struct {
    token: []const u8,

    pub fn toJson(self: @This(), comptime options: std.json.StringifyOptions) !void {
        try options.writer.writeByte('{');
        try options.writer.writeString("\"token\":\"");
        try options.writer.writeSlice(self.token);
        try options.writer.writeString("\"}");
    }
};

// Same approach: rename the field to avoid the `error` keyword
const DeleteResponse = struct {
    success: bool,
    err_msg: ?[]const u8,

    pub fn toJson(self: @This(), comptime options: std.json.StringifyOptions) !void {
        try options.writer.writeByte('{');

        // "success": ...
        try options.writer.writeString("\"success\":");
        if (self.success) {
            try options.writer.writeString("true");
        } else {
            try options.writer.writeString("false");
        }

        // "error": ...
        try options.writer.writeString(",\"error\":");
        if (self.err_msg) |actual_err| {
            try options.writer.writeString("\"");
            try options.writer.writeSlice(actual_err);
            try options.writer.writeString("\"");
        } else {
            try options.writer.writeString("null");
        }

        try options.writer.writeByte('}');
    }
};

// -------------------- Global State -------------------- //

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const UserMap = std.hash_map.HashMap(
    []const u8,
    User,
    std.hash_map.StringHasher,
    std.hash_map.default_max_load_percentage,
);
var users = UserMap.init(gpa.allocator());

// -------------------- Helper Functions -------------------- //

fn hashPassword(password: []const u8) ![crypto.hash.sha2.Sha256.digest_length]u8 {
    var hash: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hmac = crypto.auth.hmac.sha2.HmacSha256.init(SECRET_KEY);
    hmac.update(password);
    hmac.final(&hash);
    return hash;
}

fn generateJwt(allocator: Allocator, email: []const u8) ![]u8 {
    const header = JwtHeader{ .alg = "HS256", .typ = "JWT" };
    const payload = JwtPayload{ .email = email };

    const header_json = try std.json.stringifyAlloc(allocator, header, .{});
    defer allocator.free(header_json);
    const payload_json = try std.json.stringifyAlloc(allocator, payload, .{});
    defer allocator.free(payload_json);

    const header_encoded = try base64.standard.Encoder.encode(allocator, header_json);
    defer allocator.free(header_encoded);
    const payload_encoded = try base64.standard.Encoder.encode(allocator, payload_json);
    defer allocator.free(payload_encoded);

    const signature_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_encoded, payload_encoded });
    defer allocator.free(signature_input);

    var signature: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hmac = crypto.auth.hmac.sha2.HmacSha256.init(SECRET_KEY);
    hmac.update(signature_input);
    hmac.final(&signature);

    const signature_encoded = try base64.standard.Encoder.encode(allocator, &signature);
    defer allocator.free(signature_encoded);

    return try std.fmt.allocPrint(
        allocator,
        "{s}.{s}.{s}",
        .{ header_encoded, payload_encoded, signature_encoded },
    );
}

fn verifyJwt(allocator: Allocator, token: []const u8) !?JwtPayload {
    var parts = std.mem.split(u8, token, ".");
    const header_encoded = parts.next() orelse return null;
    const payload_encoded = parts.next() orelse return null;
    const signature_encoded = parts.next() orelse return null;

    const signature_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_encoded, payload_encoded });
    defer allocator.free(signature_input);

    var expected_signature: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hmac = crypto.auth.hmac.sha2.HmacSha256.init(SECRET_KEY);
    hmac.update(signature_input);
    hmac.final(&expected_signature);

    const expected_signature_encoded = try base64.standard.Encoder.encode(allocator, &expected_signature);
    defer allocator.free(expected_signature_encoded);

    if (!mem.eql(u8, signature_encoded, expected_signature_encoded)) {
        return null; // invalid signature
    }

    const payload_decoded = try base64.standard.Decoder.decode(allocator, payload_encoded);
    defer allocator.free(payload_decoded);

    const payload_val = try std.json.parse(payload_decoded, .{ .allocator = allocator });
    defer payload_val.deinit();

    const payload_obj = payload_val.objectZ() catch {
        return null;
    };

    const email_val = payload_obj.get("email") orelse return null;
    const email = email_val.stringZ() catch {
        return null;
    };

    return JwtPayload{ .email = email };
}

// -------------------- HTTP Handling -------------------- //

fn handleRequest(allocator: Allocator, stream: net.Stream) !void {
    const buf: [4096]u8 = undefined;
    const bytes_read = try stream.read(&buf);
    if (bytes_read == 0) return;

    const request = buf[0..bytes_read];

    const lines = std.mem.split(u8, request, "\r\n");
    const first_line = lines.next() orelse return RequestError.InvalidRequest;
    const method_parts = std.mem.split(u8, first_line, " ");
    const method = method_parts.next() orelse return RequestError.InvalidRequest;
    const path = method_parts.next() orelse return RequestError.InvalidRequest;

    var body: []const u8 = "";
    while (lines.next()) |line| {
        if (line.len == 0) {
            body = lines.rest();
            break;
        }
    }

    if (mem.eql(u8, path, "/register") and mem.eql(u8, method, "POST")) {
        try handleRegister(allocator, stream, body);
    } else if (mem.eql(u8, path, "/login") and mem.eql(u8, method, "POST")) {
        try handleLogin(allocator, stream, body);
    } else if (mem.eql(u8, path, "/delete") and mem.eql(u8, method, "DELETE")) {
        try handleDelete(allocator, stream, request);
    } else {
        const response = ErrorResponse{ .err_msg = "Not Found" };
        try sendJson(stream, 404, response);
    }
}

fn handleRegister(allocator: Allocator, stream: net.Stream, body: []const u8) !void {
    const body_val = try std.json.parse(body, .{ .allocator = allocator });
    defer body_val.deinit();

    const obj = body_val.objectZ() catch {
        const response = ErrorResponse{ .err_msg = "Invalid JSON" };
        return sendJson(stream, 400, response);
    };

    const email_val = obj.get("email") orelse {
        const response = ErrorResponse{ .err_msg = "Missing email" };
        return sendJson(stream, 400, response);
    };
    const password_val = obj.get("password") orelse {
        const response = ErrorResponse{ .err_msg = "Missing password" };
        return sendJson(stream, 400, response);
    };

    const email = email_val.stringZ() catch {
        const response = ErrorResponse{ .err_msg = "Email must be string" };
        return sendJson(stream, 400, response);
    };
    const password = password_val.stringZ() catch {
        const response = ErrorResponse{ .err_msg = "Password must be string" };
        return sendJson(stream, 400, response);
    };

    if (users.get(email)) |_| {
        const response = ErrorResponse{ .err_msg = "User already exists" };
        return sendJson(stream, 400, response);
    }

    const password_hash = try hashPassword(password);
    const user = User{
        .email = try allocator.dupe(u8, email),
        .password_hash = password_hash,
    };
    try users.put(email, user);

    const token = try generateJwt(allocator, email);
    defer allocator.free(token);

    const response = TokenResponse{ .token = token };
    try sendJson(stream, 200, response);
}

fn handleLogin(allocator: Allocator, stream: net.Stream, body: []const u8) !void {
    const body_val = try std.json.parse(body, .{ .allocator = allocator });
    defer body_val.deinit();

    const obj = body_val.objectZ() catch {
        const response = ErrorResponse{ .err_msg = "Invalid JSON" };
        return sendJson(stream, 400, response);
    };

    const email_val = obj.get("email") orelse {
        const response = ErrorResponse{ .err_msg = "Missing email" };
        return sendJson(stream, 400, response);
    };
    const password_val = obj.get("password") orelse {
        const response = ErrorResponse{ .err_msg = "Missing password" };
        return sendJson(stream, 400, response);
    };

    const email = email_val.stringZ() catch {
        const response = ErrorResponse{ .err_msg = "Email must be string" };
        return sendJson(stream, 400, response);
    };
    const password = password_val.stringZ() catch {
        const response = ErrorResponse{ .err_msg = "Password must be string" };
        return sendJson(stream, 400, response);
    };

    const user = users.get(email) orelse {
        const response = ErrorResponse{ .err_msg = "Invalid credentials" };
        return sendJson(stream, 401, response);
    };

    const password_hash = try hashPassword(password);
    if (!mem.eql(u8, &password_hash, &user.password_hash)) {
        const response = ErrorResponse{ .err_msg = "Invalid credentials" };
        return sendJson(stream, 401, response);
    }

    const token = try generateJwt(allocator, email);
    defer allocator.free(token);

    const response = TokenResponse{ .token = token };
    try sendJson(stream, 200, response);
}

fn handleDelete(allocator: Allocator, stream: net.Stream, request: []const u8) !void {
    var lines = std.mem.split(u8, request, "\r\n");
    _ = lines.next(); // skip request line
    var auth_header: ?[]const u8 = null;

    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "Authorization: ")) {
            auth_header = line["Authorization: ".len..];
            break;
        }
    }

    const header = auth_header orelse {
        const response = ErrorResponse{ .err_msg = "Missing Authorization header" };
        return sendJson(stream, 401, response);
    };

    if (!std.mem.startsWith(u8, header, "Bearer ")) {
        const response = ErrorResponse{ .err_msg = "Malformed Authorization header" };
        return sendJson(stream, 401, response);
    }

    const token = header["Bearer ".len..];
    const payload = (try verifyJwt(allocator, token)) orelse {
        const response = ErrorResponse{ .err_msg = "Invalid or expired token" };
        return sendJson(stream, 401, response);
    };

    if (users.remove(payload.email)) {
        const response = DeleteResponse{ .success = true, .err_msg = null };
        try sendJson(stream, 200, response);
    } else {
        const response = DeleteResponse{ .success = false, .err_msg = "User not found" };
        try sendJson(stream, 400, response);
    }
}

// Send an HTTP response with status and JSON
fn sendJson(stream: net.Stream, status: u16, response: anytype) !void {
    const header = switch (status) {
        200 => "HTTP/1.1 200 OK\r\n",
        400 => "HTTP/1.1 400 Bad Request\r\n",
        401 => "HTTP/1.1 401 Unauthorized\r\n",
        404 => "HTTP/1.1 404 Not Found\r\n",
        else => "HTTP/1.1 500 Internal Server Error\r\n",
    };

    try stream.writeAll(header);
    try stream.writeAll("Content-Type: application/json\r\n\r\n");

    try std.json.stringify(response, .{}, stream.writer());
    try stream.writeAll("\r\n");
}

// -------------------- Entry Point -------------------- //

pub fn main() !void {
    defer users.deinit();
    defer _ = gpa.deinit();

    const address = try net.Address.parseIp("127.0.0.1", PORT);
    var server = try net.StreamServer.init(.{});
    defer server.deinit();

    try server.listen(address);
    std.debug.print("Server listening on port {d}\n", .{PORT});

    while (true) {
        const connection = try server.accept();
        defer connection.stream.close();

        handleRequest(gpa.allocator(), connection.stream) catch |err| {
            std.debug.print("Error handling request: {}\n", .{err});
        };
    }
}
