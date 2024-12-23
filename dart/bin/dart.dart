import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

void main() async {
  final users = <String, String>{}; // In-memory storage for users
  const secretKey = 'your-secret-key'; // Secret key for signing JWT

  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 3000);
  print('Listening on localhost:${server.port}');

  await for (HttpRequest request in server) {
    final path = request.uri.path;
    if (path == '/register' && request.method == 'POST') {
      await handleRegister(request, users);
    } else if (path == '/login' && request.method == 'POST') {
      await handleLogin(request, users, secretKey);
    } else if (path == '/delete' && request.method == 'DELETE') {
      await handleDelete(request, users, secretKey);
    } else {
      request.response
        ..statusCode = HttpStatus.notFound
        ..write(jsonEncode({'error': 'Not Found'}))
        ..close();
    }
  }
}

Future<void> handleRegister(HttpRequest request, Map<String, String> users) async {
  final body = await utf8.decoder.bind(request).join();
  final data = jsonDecode(body);
  final email = data['email'] as String?;
  final password = data['password'] as String?;

  if (email == null || password == null) {
    request.response
      ..statusCode = HttpStatus.badRequest
      ..write(jsonEncode({'error': 'Email and password are required'}))
      ..close();
    return;
  }

  if (users.containsKey(email)) {
    request.response
      ..statusCode = HttpStatus.conflict
      ..write(jsonEncode({'error': 'User already exists'}))
      ..close();
    return;
  }

  final hashedPassword = sha256.convert(utf8.encode(password)).toString();
  users[email] = hashedPassword;

  final token = generateJWT(email, 'your-secret-key');
  request.response
    ..statusCode = HttpStatus.created
    ..write(jsonEncode({'message': 'User registered', 'token': token}))
    ..close();
}

Future<void> handleLogin(HttpRequest request, Map<String, String> users, String secretKey) async {
  final body = await utf8.decoder.bind(request).join();
  final data = jsonDecode(body);
  final email = data['email'] as String?;
  final password = data['password'] as String?;

  if (email == null || password == null) {
    request.response
      ..statusCode = HttpStatus.badRequest
      ..write(jsonEncode({'error': 'Email and password are required'}))
      ..close();
    return;
  }

  final hashedPassword = sha256.convert(utf8.encode(password)).toString();
  if (users[email] != hashedPassword) {
    request.response
      ..statusCode = HttpStatus.unauthorized
      ..write(jsonEncode({'error': 'Invalid email or password'}))
      ..close();
    return;
  }

  final token = generateJWT(email, secretKey);
  request.response
    ..statusCode = HttpStatus.ok
    ..write(jsonEncode({'message': 'Login successful', 'token': token}))
    ..close();
}

Future<void> handleDelete(HttpRequest request, Map<String, String> users, String secretKey) async {
  final authHeader = request.headers.value('authorization');
  if (authHeader == null) {
    request.response
      ..statusCode = HttpStatus.unauthorized
      ..write(jsonEncode({'error': 'Missing Authorization header.'}))
      ..close();
    return;
  }

  final parts = authHeader.split(' ');
  if (parts.length != 2 || parts[0] != 'Bearer') {
    request.response
      ..statusCode = HttpStatus.unauthorized
      ..write(jsonEncode({'error': 'Malformed Authorization header.'}))
      ..close();
    return;
  }

  final token = parts[1];
  try {
    final jwt = JWT.verify(token, SecretKey(secretKey));
    final email = jwt.payload['email'] as String?;

    if (email == null || !users.containsKey(email)) {
      request.response
        ..statusCode = HttpStatus.badRequest
        ..write(jsonEncode({'success': false, 'error': 'User not found.'}))
        ..close();
      return;
    }

    users.remove(email);
    request.response
      ..statusCode = HttpStatus.ok
      ..write(jsonEncode({'success': true}))
      ..close();
  } catch (e) {
    request.response
      ..statusCode = HttpStatus.unauthorized
      ..write(jsonEncode({'error': 'Invalid or expired token.'}))
      ..close();
  }
}

String generateJWT(String email, String secretKey) {
  final jwt = JWT({'email': email});
  return jwt.sign(SecretKey(secretKey));
}
