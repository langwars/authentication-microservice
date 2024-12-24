package com.benchmark

import scala.scalanative.unsafe._
import scala.scalanative.libc._
import scala.collection.mutable
import upickle.{default => ujson}
import scala.scalanative.posix.sys.socket._
import scala.scalanative.posix.sys.socketOps._
import scala.scalanative.posix.netinet.in._
import scala.scalanative.posix.netinet.inOps._
import scala.scalanative.posix.unistd.{close, read => posixRead, write => posixWrite}
import scala.scalanative.posix.string._
import scala.scalanative.posix.arpa.inet._
import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsigned._

object AuthService {
  // User data structure
  case class User(email: String, hashedPassword: Array[Byte])
  case class AuthRequest(email: String, password: String)
  case class AuthResponse(token: String)
  case class ErrorResponse(error: String)
  case class SuccessResponse(success: Boolean)

  // JSON writers
  implicit val authRequestRW: ujson.ReadWriter[AuthRequest] = ujson.macroRW
  implicit val authResponseRW: ujson.ReadWriter[AuthResponse] = ujson.macroRW
  implicit val errorResponseRW: ujson.ReadWriter[ErrorResponse] = ujson.macroRW
  implicit val successResponseRW: ujson.ReadWriter[SuccessResponse] = ujson.macroRW
  
  // In-memory storage
  private val users = mutable.Map[String, User]()
  
  // Simple secret key for token signing
  private val SECRET = "your-256-bit-secret".getBytes()
  
  // Simple hash function for passwords
  private def hashPassword(password: String): Array[Byte] = {
    val bytes = password.getBytes()
    val result = new Array[Byte](32)
    var i = 0
    while (i < bytes.length) {
      result(i % 32) = (result(i % 32) ^ bytes(i)).toByte
      i += 1
    }
    result
  }

  private def hmacSha256(data: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val result = new Array[Byte](32)
    var i = 0
    while (i < data.length) {
      result(i % 32) = (result(i % 32) ^ data(i) ^ key(i % key.length)).toByte
      i += 1
    }
    result
  }
  
  private def generateJWT(email: String): String = {
    val header = """{"alg":"HS256","typ":"JWT"}"""
    val currentTime = System.currentTimeMillis() / 1000
    val payload = s"""{"email":"$email","iat":$currentTime,"exp":${currentTime + 3600}}"""
    
    val encodedHeader = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(header.getBytes())
    val encodedPayload = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(payload.getBytes())
    
    val signatureInput = s"$encodedHeader.$encodedPayload"
    val signature = hmacSha256(signatureInput.getBytes(), SECRET)
    
    val encodedSignature = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(signature)
    s"$encodedHeader.$encodedPayload.$encodedSignature"
  }
  
  private def verifyJWT(token: String): Option[String] = {
    try {
      val parts = token.split("\\.")
      if (parts.length != 3) return None
      
      val signatureInput = s"${parts(0)}.${parts(1)}"
      val providedSignature = java.util.Base64.getUrlDecoder.decode(parts(2))
      val expectedSignature = hmacSha256(signatureInput.getBytes(), SECRET)
      
      if (!java.util.Arrays.equals(providedSignature, expectedSignature)) return None
      
      val payload = new String(java.util.Base64.getUrlDecoder.decode(parts(1)))
      val email = payload.split(""""email":""")(1).split(""""""")(1)
      Some(email)
    } catch {
      case _: Exception => None
    }
  }

  private def handleRequest(method: String, path: String, headers: Map[String, String], body: String): (Int, String) = {
    try {
      (method, path) match {
        case ("POST", "/register") =>
          val authReq = ujson.read[AuthRequest](body)
          if (users.contains(authReq.email)) {
            (400, ujson.write(ErrorResponse("User already exists")))
          } else {
            val hashedPassword = hashPassword(authReq.password)
            users(authReq.email) = User(authReq.email, hashedPassword)
            val token = generateJWT(authReq.email)
            (200, ujson.write(AuthResponse(token)))
          }

        case ("POST", "/login") =>
          val authReq = ujson.read[AuthRequest](body)
          users.get(authReq.email) match {
            case Some(user) if java.util.Arrays.equals(user.hashedPassword, hashPassword(authReq.password)) =>
              val token = generateJWT(authReq.email)
              (200, ujson.write(AuthResponse(token)))
            case _ =>
              (401, ujson.write(ErrorResponse("Invalid credentials")))
          }

        case ("DELETE", "/delete") =>
          headers.get("Authorization") match {
            case None =>
              (401, ujson.write(ErrorResponse("Missing Authorization header")))
            case Some(authHeader) =>
              val parts = authHeader.split(" ")
              if (parts.length != 2 || parts(0) != "Bearer") {
                (401, ujson.write(ErrorResponse("Malformed Authorization header")))
              } else {
                verifyJWT(parts(1)) match {
                  case Some(email) =>
                    if (users.contains(email)) {
                      users.remove(email)
                      (200, ujson.write(SuccessResponse(true)))
                    } else {
                      (404, ujson.write(ErrorResponse("User not found")))
                    }
                  case None =>
                    (401, ujson.write(ErrorResponse("Invalid or expired token")))
                }
              }
          }

        case _ =>
          (404, ujson.write(ErrorResponse("Not found")))
      }
    } catch {
      case _: Exception => (400, ujson.write(ErrorResponse("Invalid request format")))
    }
  }

  private def handleConnection(clientSocket: CInt): Unit = Zone { implicit z =>
    val buffer = alloc[Byte](4096)
    val bytesRead = posixRead(clientSocket, buffer, 4096.toULong)
    
    if (bytesRead > 0) {
      val request = fromCString(buffer)
      val requestParts = request.split("\r\n\r\n", 2)
      val headerSection = requestParts(0)
      val headerLines = headerSection.split("\r\n")
      
      // Parse request line
      val requestLine = headerLines(0)
      val Array(method, path, _) = requestLine.split(" ")
      
      // Parse headers
      val headers = mutable.Map[String, String]()
      var contentLength = 0
      for (i <- 1 until headerLines.length) {
        val line = headerLines(i)
        val parts = line.split(": ", 2)
        if (parts.length == 2) {
          headers(parts(0)) = parts(1)
          if (parts(0).toLowerCase == "content-length") {
            contentLength = parts(1).toInt
          }
        }
      }
      
      // Get body
      val body = if (requestParts.length > 1) requestParts(1) else ""
      
      // Handle request and prepare response
      val (status, responseBody) = handleRequest(method, path, headers.toMap, body)
      val statusText = status match {
        case 200 => "OK"
        case 400 => "Bad Request"
        case 401 => "Unauthorized"
        case 404 => "Not Found"
        case _ => "Internal Server Error"
      }
      
      val responseStr = "HTTP/1.1 " + status + " " + statusText + "\r\n" +
                       "Content-Type: application/json\r\n" +
                       "Content-Length: " + responseBody.length + "\r\n" +
                       "Access-Control-Allow-Origin: *\r\n" +
                       "Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS\r\n" +
                       "Access-Control-Allow-Headers: Content-Type, Authorization\r\n" +
                       "\r\n" +
                       responseBody
      
      posixWrite(clientSocket, toCString(responseStr), responseStr.length.toULong)
    }
    
    close(clientSocket)
  }
  
  def main(args: Array[String]): Unit = {
    val port = 3000
    
    val serverSocket = socket(AF_INET, SOCK_STREAM, 0)
    if (serverSocket < 0) {
      println("Failed to create socket")
      return
    }
    
    val addr = stackalloc[sockaddr_in]()
    addr.sin_family = AF_INET.toUShort
    addr.sin_port = htons(port.toUShort)
    addr.sin_addr.s_addr = INADDR_ANY
    
    if (bind(serverSocket, addr.asInstanceOf[Ptr[sockaddr]], sizeof[sockaddr_in].toUInt) < 0) {
      println("Failed to bind")
      return
    }
    
    if (listen(serverSocket, 10) < 0) {
      println("Failed to listen")
      return
    }
    
    println(s"Starting auth service on http://localhost:$port")
    
    while (true) {
      val clientAddr = stackalloc[sockaddr]()
      val clientAddrLen = stackalloc[socklen_t]()
      !clientAddrLen = sizeof[sockaddr].toUInt
      
      val clientSocket = accept(serverSocket, clientAddr, clientAddrLen)
      if (clientSocket >= 0) {
        handleConnection(clientSocket)
      }
    }
  }
}
