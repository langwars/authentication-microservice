import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

import java.util.HashMap;
import java.util.Map;

/**
 * High-Performance Authentication Microservice
 * Uses only native Java APIs for maximum performance:
 * - com.sun.net.httpserver for HTTP server
 * - javax.crypto for cryptography
 * - ConcurrentHashMap for thread-safe in-memory storage
 */
public class AuthService {
    private static final int PORT = 3000;
    private static final String SECRET_KEY = "YOUR_SUPER_SECRET";
    private static final ConcurrentHashMap<String, String> users = new ConcurrentHashMap<>();

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        // Create a thread pool with fixed number of threads for better resource management
        server.setExecutor(Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()));
        
        server.createContext("/register", new RegisterHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/delete", new DeleteHandler());
        
        server.start();
        System.out.println("Server started on port " + PORT);
    }

    private static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
                return;
            }

            try {
                Map<String, String> requestBody = parseRequestBody(exchange.getRequestBody());
                String email = requestBody.get("email");
                String password = requestBody.get("password");

                if (email == null || password == null) {
                    sendResponse(exchange, 400, "{\"error\": \"Invalid JSON or missing fields\"}");
                    return;
                }

                if (users.containsKey(email)) {
                    sendResponse(exchange, 400, "{\"error\": \"User already exists\"}");
                    return;
                }

                String hashedPassword = hashPassword(password);
                users.put(email, hashedPassword);

                String token = generateJWT(email);
                sendResponse(exchange, 200, "{\"token\": \"" + token + "\"}");
            } catch (Exception e) {
                sendResponse(exchange, 400, "{\"error\": \"Invalid request\"}");
            }
        }
    }

    private static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
                return;
            }

            try {
                Map<String, String> requestBody = parseRequestBody(exchange.getRequestBody());
                String email = requestBody.get("email");
                String password = requestBody.get("password");

                if (email == null || password == null) {
                    sendResponse(exchange, 400, "{\"error\": \"Invalid JSON or missing fields\"}");
                    return;
                }

                String storedHash = users.get(email);
                if (storedHash == null) {
                    sendResponse(exchange, 401, "{\"error\": \"Invalid credentials\"}");
                    return;
                }

                String givenHash = hashPassword(password);
                if (!storedHash.equals(givenHash)) {
                    sendResponse(exchange, 401, "{\"error\": \"Invalid credentials\"}");
                    return;
                }

                String token = generateJWT(email);
                sendResponse(exchange, 200, "{\"token\": \"" + token + "\"}");
            } catch (Exception e) {
                sendResponse(exchange, 400, "{\"error\": \"Invalid request\"}");
            }
        }
    }

    private static class DeleteHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"DELETE".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
                return;
            }

            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (authHeader == null) {
                sendResponse(exchange, 401, "{\"error\": \"Missing Authorization header\"}");
                return;
            }

            String[] parts = authHeader.split(" ");
            if (parts.length != 2 || !"Bearer".equals(parts[0])) {
                sendResponse(exchange, 401, "{\"error\": \"Malformed Authorization header\"}");
                return;
            }

            try {
                String email = verifyJWT(parts[1]);
                if (email == null) {
                    sendResponse(exchange, 401, "{\"error\": \"Invalid or expired token\"}");
                    return;
                }

                if (users.remove(email) != null) {
                    sendResponse(exchange, 200, "{\"success\": true}");
                } else {
                    sendResponse(exchange, 400, "{\"success\": false, \"error\": \"User not found\"}");
                }
            } catch (Exception e) {
                sendResponse(exchange, 401, "{\"error\": \"Invalid token\"}");
            }
        }
    }

    private static Map<String, String> parseRequestBody(InputStream is) throws IOException {
        byte[] buffer = new byte[1024];
        int bytesRead;
        StringBuilder requestBody = new StringBuilder();
        while ((bytesRead = is.read(buffer)) != -1) {
            requestBody.append(new String(buffer, 0, bytesRead));
        }

        // Simple JSON parsing for {"email": "value", "password": "value"}
        String body = requestBody.toString();
        Map<String, String> result = new HashMap<>();
        
        // Remove brackets and split by comma
        body = body.replaceAll("[{}\"]", "");
        String[] pairs = body.split(",");
        
        for (String pair : pairs) {
            String[] keyValue = pair.split(":");
            if (keyValue.length == 2) {
                result.put(keyValue[0].trim(), keyValue[1].trim());
            }
        }
        
        return result;
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }

    private static String hashPassword(String password) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmac.init(secretKey);
            byte[] hash = hmac.doFinal(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    private static String generateJWT(String email) {
        try {
            // Create JWT header and payload
            String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                String.format("{\"email\":\"%s\"}", email).getBytes(StandardCharsets.UTF_8));

            // Create signature
            String signatureInput = header + "." + payload;
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmac.init(secretKey);
            byte[] signature = hmac.doFinal(signatureInput.getBytes(StandardCharsets.UTF_8));
            String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);

            return header + "." + payload + "." + encodedSignature;
        } catch (Exception e) {
            throw new RuntimeException("Error generating JWT", e);
        }
    }

    private static String verifyJWT(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return null;

            // Verify signature
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmac.init(secretKey);
            byte[] signatureBytes = hmac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
            String computedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

            if (!computedSignature.equals(parts[2])) return null;

            // Decode payload
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            // Simple JSON parsing to extract email
            return payload.split("\"email\":\"")[1].split("\"")[0];
        } catch (Exception e) {
            return null;
        }
    }
}
