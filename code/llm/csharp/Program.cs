using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Buffers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService;

// Record types for request models
public record struct RegisterRequest(string Email, string Password);
public record struct LoginRequest(string Email, string Password);

public class Program
{
    private static readonly ConcurrentDictionary<string, byte[]> users = new();
    private static readonly byte[] secretKey = Encoding.UTF8.GetBytes("YOUR_SUPER_SECRET");
    private static readonly JsonSerializerOptions jsonOptions = new() { PropertyNameCaseInsensitive = true };
    private static readonly string jwtHeader;

    static Program()
    {
        var jwtHeaderBytes = JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" });
        jwtHeader = Convert.ToBase64String(jwtHeaderBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        ConfigureBuilder(builder);
        
        var app = builder.Build();
        ConfigureApp(app);
        
        app.Run("http://localhost:3000");
    }

    private static void ConfigureBuilder(WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AllowSynchronousIO = false;
            options.Limits.MaxConcurrentConnections = null;
            options.Limits.MaxConcurrentUpgradedConnections = null;
            options.Limits.MaxRequestBodySize = 1024;
            options.Limits.MinRequestBodyDataRate = null;
            options.Limits.MinResponseDataRate = null;
        });
    }

    private static void ConfigureApp(WebApplication app)
    {
        app.MapPost("/register", RegisterHandler);
        app.MapPost("/login", LoginHandler);
        app.MapDelete("/delete", DeleteHandler);
    }

    private static byte[] HashPassword(byte[] password)
    {
        using var hmac = new HMACSHA256(secretKey);
        return hmac.ComputeHash(password);
    }

    private static string GenerateJWT(ReadOnlySpan<char> email)
    {
        var payloadJson = $"{{\"email\":\"{email}\"}}";
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var payload = Convert.ToBase64String(payloadBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        
        var signatureInput = string.Create(jwtHeader.Length + 1 + payload.Length, (jwtHeader, payload), (span, state) =>
        {
            state.jwtHeader.CopyTo(span);
            span[state.jwtHeader.Length] = '.';
            state.payload.CopyTo(span.Slice(state.jwtHeader.Length + 1));
        });

        using var hmac = new HMACSHA256(secretKey);
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureInput));
        var signature = Convert.ToBase64String(signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        
        return string.Create(signatureInput.Length + 1 + signature.Length, (signatureInput, signature), (span, state) =>
        {
            state.signatureInput.CopyTo(span);
            span[state.signatureInput.Length] = '.';
            state.signature.CopyTo(span.Slice(state.signatureInput.Length + 1));
        });
    }

    private static (bool isValid, string? email) VerifyJWT(ReadOnlySpan<char> token)
    {
        var firstDot = token.IndexOf('.');
        if (firstDot == -1) return (false, null);
        
        var secondDot = token.Slice(firstDot + 1).IndexOf('.');
        if (secondDot == -1) return (false, null);
        secondDot += firstDot + 1;

        var signatureInput = token.Slice(0, secondDot);
        var signature = token.Slice(secondDot + 1);

        using var hmac = new HMACSHA256(secretKey);
        var expectedSignature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureInput.ToString())))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        if (!signature.SequenceEqual(expectedSignature)) return (false, null);

        var payload = token.Slice(firstDot + 1, secondDot - firstDot - 1);
        try
        {
            var payloadJson = Encoding.UTF8.GetString(
                Convert.FromBase64String(
                    payload.ToString().Replace('-', '+').Replace('_', '/').PadRight(4 * ((payload.Length + 3) / 4), '=')));
            using var doc = JsonDocument.Parse(payloadJson);
            return (true, doc.RootElement.GetProperty("email").GetString());
        }
        catch
        {
            return (false, null);
        }
    }

    private static async Task<IResult> RegisterHandler(HttpContext context)
    {
        if (!context.Request.HasJsonContentType())
            return Results.BadRequest();

        try
        {
            var request = await JsonSerializer.DeserializeAsync<RegisterRequest>(
                context.Request.Body, jsonOptions);

            if (request == null || string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                return Results.BadRequest();

            var passwordHash = HashPassword(Encoding.UTF8.GetBytes(request.Password));
            
            if (!users.TryAdd(request.Email, passwordHash))
                return Results.BadRequest();

            var token = GenerateJWT(request.Email);
            return Results.Ok(new { token });
        }
        catch
        {
            return Results.BadRequest();
        }
    }

    private static async Task<IResult> LoginHandler(HttpContext context)
    {
        if (!context.Request.HasJsonContentType())
            return Results.BadRequest();

        try
        {
            var request = await JsonSerializer.DeserializeAsync<LoginRequest>(
                context.Request.Body, jsonOptions);

            if (request == null || string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                return Results.BadRequest();

            if (!users.TryGetValue(request.Email, out var storedHash))
                return Results.Unauthorized();

            var givenHash = HashPassword(Encoding.UTF8.GetBytes(request.Password));
            if (!storedHash.AsSpan().SequenceEqual(givenHash))
                return Results.Unauthorized();

            var token = GenerateJWT(request.Email);
            return Results.Ok(new { token });
        }
        catch
        {
            return Results.BadRequest();
        }
    }

    private static IResult DeleteHandler(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader))
            return Results.Unauthorized();

        ReadOnlySpan<char> headerSpan = authHeader;
        if (!headerSpan.StartsWith("Bearer "))
            return Results.Unauthorized();

        var token = headerSpan.Slice(7);
        var (isValid, email) = VerifyJWT(token);
        if (!isValid || email == null)
            return Results.Unauthorized();

        return users.TryRemove(email, out _) 
            ? Results.Ok(new { success = true }) 
            : Results.BadRequest(new { success = false, error = "User not found." });
    }
}
