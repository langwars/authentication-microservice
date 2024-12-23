import NIO
import NIOHTTP1
import Foundation
import Crypto

// MARK: - Models

struct User {
    let email: String
    let hashedPassword: String
}

private let usersQueue = DispatchQueue(label: "com.auth.users")
private var users: [String: User] = [:]   // In-memory user storage
let jwtSecret = "MY_SUPER_SECRET_123"

// MARK: - Utilities

func sendJSON(
    _ channel: Channel,
    status: HTTPResponseStatus,
    json: Any
) {
    var responseData: Data
    do {
        if let dict = json as? [String: Any] {
            responseData = try JSONSerialization.data(withJSONObject: dict, options: [])
        } else if let arr = json as? [Any] {
            responseData = try JSONSerialization.data(withJSONObject: arr, options: [])
        } else {
            responseData = Data()
        }
    } catch {
        responseData = Data()
    }
    
    let headers = HTTPHeaders([
        ("Content-Type", "application/json"),
        ("Content-Length", "\(responseData.count)")
    ])
    
    let head = HTTPResponseHead(
        version: HTTPVersion(major: 1, minor: 1),
        status: status,
        headers: headers
    )
    
    var buffer = channel.allocator.buffer(capacity: responseData.count)
    buffer.writeBytes(responseData)

    let partHead = HTTPServerResponsePart.head(head)
    let partBody = HTTPServerResponsePart.body(.byteBuffer(buffer))
    let partEnd = HTTPServerResponsePart.end(nil)
    
    channel.write(partHead, promise: nil)
    channel.write(partBody, promise: nil)
    
    channel.writeAndFlush(partEnd).whenComplete { result in
        if case .failure = result {
            channel.close(promise: nil)
        }
    }
}


func getBodyData(_ bodyParts: [ByteBuffer]) -> Data {
    var fullData = Data()
    for var buffer in bodyParts {
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            fullData.append(contentsOf: bytes)
        }
    }
    return fullData
}

func parseJSONBody(_ bodyData: Data) -> [String: String]? {
    if let jsonObj = try? JSONSerialization.jsonObject(with: bodyData, options: []),
       let dict = jsonObj as? [String: String] {
        return dict
    }
    return nil
}

/// Simple SHA256 hash (not recommended for production).
func hashPassword(_ password: String) -> String {
    let inputData = Data(password.utf8)
    let hash = SHA256.hash(data: inputData)
    return hash.map { String(format: "%02x", $0) }.joined()
}

// MARK: - JWT

func signJWT(email: String, secret: String) -> String {
    let header: [String: String] = [
        "alg": "HS256",
        "typ": "JWT"
    ]
    let payload: [String: String] = [
        "email": email
        // Typically, add "exp" or other claims in production
    ]
    
    func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    // Encode header
    let headerData = try! JSONSerialization.data(withJSONObject: header, options: [])
    let headerString = base64URLEncode(headerData)
    
    // Encode payload
    let payloadData = try! JSONSerialization.data(withJSONObject: payload, options: [])
    let payloadString = base64URLEncode(payloadData)
    
    let toSign = "\(headerString).\(payloadString)"
    let key = SymmetricKey(data: Data(secret.utf8))
    let signature = HMAC<SHA256>.authenticationCode(for: Data(toSign.utf8), using: key)
    let signatureString = base64URLEncode(Data(signature))
    
    return "\(toSign).\(signatureString)"
}

func verifyJWT(_ token: String, secret: String) -> [String: Any]? {
    let segments = token.split(separator: ".").map { String($0) }
    guard segments.count == 3 else { return nil }
    let headerSegment = segments[0]
    let payloadSegment = segments[1]
    let signatureSegment = segments[2]
    
    let toSign = "\(headerSegment).\(payloadSegment)"
    let key = SymmetricKey(data: Data(secret.utf8))
    let newSignature = HMAC<SHA256>.authenticationCode(for: Data(toSign.utf8), using: key)
    let newSignatureData = Data(newSignature)
    
    guard let signatureData = base64URLDecode(signatureSegment), signatureData == newSignatureData else {
        return nil
    }
    
    guard let payloadData = base64URLDecode(payloadSegment) else {
        return nil
    }
    return (try? JSONSerialization.jsonObject(with: payloadData, options: [])) as? [String: Any]
}

private func base64URLDecode(_ base64URLString: String) -> Data? {
    var base64 = base64URLString
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 {
        base64.append("=")
    }
    return Data(base64Encoded: base64)
}

// MARK: - HTTP Handler

final class HTTPHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    
    private var bodyBuffer: [ByteBuffer] = []
    private var requestMethod: HTTPMethod = .GET
    private var requestURI: String = "/"
    private var currentAuthorizationHeader: String? = nil

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let reqPart = self.unwrapInboundIn(data)
        
        switch reqPart {
        case .head(let header):
            requestMethod = header.method
            requestURI = header.uri
            bodyBuffer.removeAll()
            currentAuthorizationHeader = header.headers["Authorization"].first
            
        case .body(let chunk):
            bodyBuffer.append(chunk)
            
        case .end:
            handleRequest(context: context)
        }
    }
    
    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }
    
    private func handleRequest(context: ChannelHandlerContext) {
        switch (requestMethod, requestURI) {
        // POST /register
        case (.POST, "/register"):
            let requestData = getBodyData(bodyBuffer)
            guard let jsonBody = parseJSONBody(requestData),
                  let email = jsonBody["email"],
                  let password = jsonBody["password"] else {
                sendJSON(
                    context.channel,
                    status: .badRequest,
                    json: ["error": "Missing email/password"]
                )
                return
            }
            
            var userExists = false
            usersQueue.sync {
                userExists = users[email] != nil
            }
            
            if userExists {
                sendJSON(
                    context.channel,
                    status: .conflict,
                    json: ["error": "User already exists"]
                )
                return
            }
            
            let hashed = hashPassword(password)
            let user = User(email: email, hashedPassword: hashed)
            usersQueue.sync {
                users[email] = user
            }
            
            let token = signJWT(email: email, secret: jwtSecret)
            sendJSON(
                context.channel,
                status: .ok,
                json: ["token": token]
            )
            
        // POST /login
        case (.POST, "/login"):
            let requestData = getBodyData(bodyBuffer)
            guard let jsonBody = parseJSONBody(requestData),
                  let email = jsonBody["email"],
                  let password = jsonBody["password"] else {
                sendJSON(
                    context.channel,
                    status: .badRequest,
                    json: ["error": "Missing email/password"]
                )
                return
            }
            
            var user: User?
            usersQueue.sync {
                user = users[email]
            }
            
            guard let user = user else {
                sendJSON(
                    context.channel,
                    status: .unauthorized,
                    json: ["error": "Invalid credentials"]
                )
                return
            }
            
            let hashed = hashPassword(password)
            guard user.hashedPassword == hashed else {
                sendJSON(
                    context.channel,
                    status: .unauthorized,
                    json: ["error": "Invalid credentials"]
                )
                return
            }
            
            let token = signJWT(email: email, secret: jwtSecret)
            sendJSON(
                context.channel,
                status: .ok,
                json: ["token": token]
            )
            
        // DELETE /delete
        case (.DELETE, "/delete"):
            guard let authorizationHeader = currentAuthorizationHeader else {
                sendJSON(
                    context.channel,
                    status: .unauthorized,
                    json: ["error": "Missing Authorization header."]
                )
                return
            }
            
            let parts = authorizationHeader.split(separator: " ")
            guard parts.count == 2, parts[0] == "Bearer" else {
                sendJSON(
                    context.channel,
                    status: .unauthorized,
                    json: ["error": "Malformed Authorization header."]
                )
                return
            }
            
            let token = String(parts[1])
            guard let payload = verifyJWT(token, secret: jwtSecret),
                  let email = payload["email"] as? String else {
                sendJSON(
                    context.channel,
                    status: .unauthorized,
                    json: ["error": "Invalid or expired token."]
                )
                return
            }
            
            var userDeleted = false
            usersQueue.sync {
                if users[email] != nil {
                    users.removeValue(forKey: email)
                    userDeleted = true
                }
            }
            
            if userDeleted {
                sendJSON(context.channel, status: .ok, json: ["success": true])
            } else {
                sendJSON(
                    context.channel,
                    status: .badRequest,
                    json: ["success": false, "error": "User not found."]
                )
            }
            
        default:
            // Unknown route
            sendJSON(
                context.channel,
                status: .notFound,
                json: ["error": "Route not found"]
            )
        }
    }
}

// MARK: - Main Entry

@main
struct AuthMicroservice {
    static func main() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline(withErrorHandling: true).flatMap {
                    channel.pipeline.addHandler(HTTPHandler())
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        
        let port = 3000
        let serverChannel = try bootstrap.bind(host: "localhost", port: port).wait()
        print("Server running on http://127.0.0.1:\(port)")
        
        // Keep running until SIGINT or SIGTERM
        try serverChannel.closeFuture.wait()
    }
}
