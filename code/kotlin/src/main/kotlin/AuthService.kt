import io.ktor.application.*
import io.ktor.features.*
import io.ktor.http.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.auth.jwt.*
import io.ktor.auth.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.util.*
import java.security.MessageDigest
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import io.ktor.serialization.*

// Data classes for requests and responses
@Serializable
data class AuthRequest(val email: String, val password: String)

@Serializable
data class AuthResponse(val token: String)

@Serializable
data class ErrorResponse(val error: String)

@Serializable
data class SuccessResponse(val success: Boolean, val error: String? = null)

class AuthService {
    // In-memory user store
    private val users = mutableMapOf<String, String>() // email -> hashed password
    private val algorithm = Algorithm.HMAC256("your-secret-key")
    private val json = Json { prettyPrint = true }

    // Hash password using SHA-256
    private fun hashPassword(password: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(password.toByteArray())
        return Base64.getEncoder().encodeToString(hash)
    }

    // Generate JWT token
    private fun generateToken(email: String): String = JWT.create()
        .withClaim("email", email)
        .withExpiresAt(Date(System.currentTimeMillis() + 3600000)) // 1 hour
        .sign(algorithm)

    // Verify JWT token
    private fun verifyToken(token: String): String? {
        return try {
            val verifier = JWT.require(algorithm).build()
            val decodedJWT = verifier.verify(token)
            decodedJWT.getClaim("email").asString()
        } catch (e: Exception) {
            null
        }
    }

    fun start() {
        embeddedServer(Netty, port = 3000) {
            install(ContentNegotiation) {
                json()
            }
            
            install(CORS) {
                method(HttpMethod.Options)
                method(HttpMethod.Get)
                method(HttpMethod.Post)
                method(HttpMethod.Delete)
                anyHost()
            }

            routing {
                post("/register") {
                    val request = call.receive<AuthRequest>()
                    
                    if (users.containsKey(request.email)) {
                        call.respond(HttpStatusCode.BadRequest, ErrorResponse("User already exists"))
                        return@post
                    }

                    users[request.email] = hashPassword(request.password)
                    val token = generateToken(request.email)
                    call.respond(AuthResponse(token))
                }

                post("/login") {
                    val request = call.receive<AuthRequest>()
                    val hashedPassword = users[request.email]

                    if (hashedPassword == null || hashedPassword != hashPassword(request.password)) {
                        call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                        return@post
                    }

                    val token = generateToken(request.email)
                    call.respond(AuthResponse(token))
                }

                delete("/delete") {
                    val authHeader = call.request.header("Authorization")
                    if (authHeader == null) {
                        call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Missing Authorization header"))
                        return@delete
                    }

                    val parts = authHeader.split(" ")
                    if (parts.size != 2 || parts[0] != "Bearer") {
                        call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Malformed Authorization header"))
                        return@delete
                    }

                    val email = verifyToken(parts[1])
                    if (email == null) {
                        call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid or expired token"))
                        return@delete
                    }

                    if (users.remove(email) != null) {
                        call.respond(SuccessResponse(true))
                    } else {
                        call.respond(HttpStatusCode.BadRequest, SuccessResponse(false, "User not found"))
                    }
                }
            }
        }.start(wait = true)
    }
}

fun main() {
    AuthService().start()
}
