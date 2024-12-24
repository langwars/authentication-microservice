# Authentication Microservice in Odin

This is a high-performance authentication microservice implemented in Odin. It provides three REST endpoints for user authentication:

- `/register` (POST): Creates a new user account
- `/login` (POST): Authenticates a user and returns a JWT
- `/delete` (DELETE): Deletes a user account (requires JWT)

## Features

- In-memory user storage for maximum performance
- Password hashing using SHA-256
- JWT-based authentication
- Proper error handling and JSON responses
- Minimal external dependencies
- Native TCP socket implementation for optimal performance

## Prerequisites

You need to have Odin installed with the following core packages:
- core:net
- core:crypto
- core:encoding/json
- core:encoding/base64
- core:strings
- core:time
- core:fmt
- core:os

## API Endpoints

### Register
```
POST /register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "secretpassword"
}

Response:
{
    "token": "<JWT_TOKEN>"
}
```

### Login
```
POST /login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "secretpassword"
}

Response:
{
    "token": "<JWT_TOKEN>"
}
```

### Delete Account
```
DELETE /delete
Authorization: Bearer <JWT_TOKEN>

Response:
{
    "success": true
}
```

## Performance Considerations

The service is designed for maximum performance:
1. Uses in-memory storage with O(1) lookups
2. Minimal memory allocations
3. Efficient password hashing
4. Direct TCP socket implementation without heavy HTTP frameworks
5. Zero-copy string operations where possible
6. Efficient JSON encoding/decoding

## Testing

You can test the endpoints using curl:

```bash
# Register a new user
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'

# Login
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'

# Delete account (replace <TOKEN> with the JWT from login/register)
curl -X DELETE http://localhost:8080/delete \
  -H "Authorization: Bearer <TOKEN>"
```
