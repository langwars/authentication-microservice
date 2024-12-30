package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/fasthttp/router"
	"github.com/golang-jwt/jwt/v4"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

type JSONResponse struct {
	Status string `json:"status"`
}

type registerResponse struct {
	Status string `json:"status"`
	Token  string `json:"token"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// We'll store user data in-memory: Key = email, Value = hashed password.
var (
	mu    sync.RWMutex
	users = make(map[string]string)
)

// A secret key for signing JWTs (in production, store securely!)
var jwtSecret = []byte("mySuperSecretKey")

func respondJSON(ctx *fasthttp.RequestCtx, statusCode int, data interface{}) {
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.SetStatusCode(statusCode)

	if data == nil {
		return
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to encode JSON: %v", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}
	ctx.SetBody(jsonBytes)
}

// generateJWT is a helper to create a new JWT with the user’s email and sign it.
func generateJWT(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		// Additional claims could go here, e.g. "exp", "iss"
	})
	return token.SignedString(jwtSecret)
}

func loginHandler(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() {
		respondJSON(ctx, fasthttp.StatusMethodNotAllowed, JSONResponse{Status: "Method not allowed"})
		return
	}

	var req registerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Printf("Failed to parse JSON body in login: %v", err)
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Bad request"})
		return
	}

	// Check if fields are present
	if req.Email == "" || req.Password == "" {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Email and password required"})
		return
	}

	mu.RLock()
	hashedPwd, found := users[req.Email]
	mu.RUnlock()

	// If the user does not exist, return 401 (unauthorized)
	if !found {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid email or password"})
		return
	}

	// Compare the stored hashed password with the incoming password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(req.Password)); err != nil {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid email or password"})
		return
	}

	// Password is correct, generate a new JWT
	signedToken, err := generateJWT(req.Email)
	if err != nil {
		log.Printf("Failed to sign JWT in login: %v", err)
		respondJSON(ctx, fasthttp.StatusInternalServerError, JSONResponse{Status: "Internal server error"})
		return
	}

	respondJSON(ctx, fasthttp.StatusOK, registerResponse{
		Status: "OK",
		Token:  signedToken,
	})
}

func registerHandler(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() {
		respondJSON(ctx, fasthttp.StatusMethodNotAllowed, JSONResponse{Status: "Method not allowed"})
		return
	}

	var req registerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Printf("Failed to parse JSON body in register: %v", err)
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Bad request"})
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Email and password required"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		respondJSON(ctx, fasthttp.StatusInternalServerError, JSONResponse{Status: "Could not process password"})
		return
	}

	mu.Lock()
	users[req.Email] = string(hashedPassword)
	mu.Unlock()

	// Generate a JWT
	signedToken, err := generateJWT(req.Email)
	if err != nil {
		log.Printf("Failed to sign JWT in register: %v", err)
		respondJSON(ctx, fasthttp.StatusInternalServerError, JSONResponse{Status: "Internal server error"})
		return
	}

	respondJSON(ctx, fasthttp.StatusOK, registerResponse{
		Status: "OK",
		Token:  signedToken,
	})
}

func deleteHandler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Method()) != fasthttp.MethodDelete {
		respondJSON(ctx, fasthttp.StatusMethodNotAllowed, JSONResponse{Status: "Method not allowed"})
		return
	}

	// Check for the Authorization header
	authHeader := string(ctx.Request.Header.Peek("Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Missing or invalid Bearer token"})
		return
	}

	tokenString := authHeader[len("Bearer "):]

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Ensure we’re using the correct signing method (HMAC)
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid token"})
		return
	}

	// Extract the claims to get the email
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid token claims"})
		return
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid email claim"})
		return
	}

	// Remove the user from the in-memory map
	mu.Lock()
	delete(users, email)
	mu.Unlock()

	respondJSON(ctx, fasthttp.StatusOK, JSONResponse{Status: "OK"})
}

func main() {
	r := router.New()
	r.POST("/login", loginHandler)
	r.POST("/register", registerHandler)
	r.DELETE("/delete", deleteHandler)

	srv := &fasthttp.Server{
		Handler:            r.Handler,
		Name:               "FastHTTP-Server",
		MaxConnsPerIP:      0,
		MaxRequestsPerConn: 0,
	}

	log.Println("Starting FastHTTP server on :3000...")
	if err := srv.ListenAndServe(":3000"); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}
