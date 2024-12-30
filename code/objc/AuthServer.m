#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <unistd.h>

// Constants
static NSString *const kSecretKey = @"YOUR_SUPER_SECRET";
static const NSUInteger kPort = 3000;

// User storage
@interface User : NSObject
@property (nonatomic, strong) NSString *hashedPassword;
@end

@implementation User
@end

// Global user dictionary
static NSMutableDictionary<NSString*, User*> *users;

// Helper functions
NSString* base64UrlEncode(NSData *data) {
    NSString *base64 = [data base64EncodedStringWithOptions:0];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"=" withString:@""];
    return base64;
}

NSString* hashPassword(NSString *password) {
    const char *cKey = [kSecretKey cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [password cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSData *hmacData = [NSData dataWithBytes:cHMAC length:sizeof(cHMAC)];
    return [hmacData base64EncodedStringWithOptions:0];
}

NSString* generateJWT(NSDictionary *payload) {
    NSDictionary *header = @{@"alg": @"HS256", @"typ": @"JWT"};
    
    NSData *headerData = [NSJSONSerialization dataWithJSONObject:header options:0 error:nil];
    NSData *payloadData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    
    NSString *encodedHeader = base64UrlEncode(headerData);
    NSString *encodedPayload = base64UrlEncode(payloadData);
    
    NSString *signatureInput = [NSString stringWithFormat:@"%@.%@", encodedHeader, encodedPayload];
    const char *cKey = [kSecretKey cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [signatureInput cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSData *signatureData = [NSData dataWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString *signature = base64UrlEncode(signatureData);
    
    return [NSString stringWithFormat:@"%@.%@.%@", encodedHeader, encodedPayload, signature];
}

NSDictionary* verifyJWT(NSString *token) {
    NSArray *parts = [token componentsSeparatedByString:@"."];
    if (parts.count != 3) return nil;
    
    NSString *encodedHeader = parts[0];
    NSString *encodedPayload = parts[1];
    NSString *signature = parts[2];
    
    // Verify signature
    NSString *signatureInput = [NSString stringWithFormat:@"%@.%@", encodedHeader, encodedPayload];
    const char *cKey = [kSecretKey cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [signatureInput cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSData *signatureData = [NSData dataWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString *expectedSignature = base64UrlEncode(signatureData);
    
    if (![signature isEqualToString:expectedSignature]) return nil;
    
    // Decode payload
    NSString *base64Payload = [encodedPayload stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    base64Payload = [base64Payload stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    NSData *payloadData = [[NSData alloc] initWithBase64EncodedString:base64Payload options:0];
    return [NSJSONSerialization JSONObjectWithData:payloadData options:0 error:nil];
}

void sendJSONResponse(NSOutputStream *outputStream, NSInteger statusCode, NSDictionary *response) {
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:response options:0 error:nil];
    NSString *headers = [NSString stringWithFormat:
                        @"HTTP/1.1 %ld OK\r\n"
                        @"Content-Type: application/json\r\n"
                        @"Content-Length: %lu\r\n"
                        @"\r\n",
                        (long)statusCode,
                        (unsigned long)jsonData.length];
    
    NSData *headerData = [headers dataUsingEncoding:NSUTF8StringEncoding];
    [outputStream write:headerData.bytes maxLength:headerData.length];
    [outputStream write:jsonData.bytes maxLength:jsonData.length];
}

// A helper to read exactly `contentLength` bytes from the request body.
NSData* readRequestBody(NSInputStream *input, NSUInteger contentLength) {
    NSMutableData *bodyData = [NSMutableData dataWithCapacity:contentLength];
    uint8_t buffer[1024];
    NSUInteger totalBytesRead = 0;
    
    while (totalBytesRead < contentLength) {
        NSUInteger bytesToRead = MIN(sizeof(buffer), contentLength - totalBytesRead);
        NSInteger bytesRead = [input read:buffer maxLength:bytesToRead];
        if (bytesRead <= 0) {
            // This could indicate an error or the stream closed prematurely
            break;
        }
        [bodyData appendBytes:buffer length:bytesRead];
        totalBytesRead += bytesRead;
    }
    return [bodyData copy];
}

// Request handlers
void handleRegister(NSInputStream *input, NSOutputStream *output, NSUInteger contentLength) {
    // Read the JSON body
    NSData *body = readRequestBody(input, contentLength);
    
    NSError *error = nil;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:body options:0 error:&error];
    
    if (error || !json[@"email"] || !json[@"password"]) {
        sendJSONResponse(output, 400, @{@"error": @"Invalid JSON or missing fields."});
        return;
    }
    
    NSString *email = json[@"email"];
    NSString *password = json[@"password"];
    
    if (users[email]) {
        sendJSONResponse(output, 400, @{@"error": @"User already exists."});
        return;
    }
    
    User *user = [[User alloc] init];
    user.hashedPassword = hashPassword(password);
    users[email] = user;
    
    NSString *token = generateJWT(@{@"email": email});
    sendJSONResponse(output, 200, @{@"token": token});
}

void handleLogin(NSInputStream *input, NSOutputStream *output, NSUInteger contentLength) {
    // Read the JSON body
    NSData *body = readRequestBody(input, contentLength);
    
    NSError *error = nil;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:body options:0 error:&error];
    
    if (error || !json[@"email"] || !json[@"password"]) {
        sendJSONResponse(output, 400, @{@"error": @"Invalid JSON or missing fields."});
        return;
    }
    
    NSString *email = json[@"email"];
    NSString *password = json[@"password"];
    User *user = users[email];
    
    if (!user || ![user.hashedPassword isEqualToString:hashPassword(password)]) {
        sendJSONResponse(output, 401, @{@"error": @"Invalid credentials."});
        return;
    }
    
    NSString *token = generateJWT(@{@"email": email});
    sendJSONResponse(output, 200, @{@"token": token});
}

void handleDelete(NSInputStream *input, NSOutputStream *output, NSDictionary *headers) {
    // This DELETE route does not read a body in the original code, so we skip readRequestBody here.
    NSString *authHeader = headers[@"Authorization"];
    if (!authHeader) {
        sendJSONResponse(output, 401, @{@"error": @"Missing Authorization header."});
        return;
    }
    
    NSArray *parts = [authHeader componentsSeparatedByString:@" "];
    if (parts.count != 2 || ![parts[0] isEqualToString:@"Bearer"]) {
        sendJSONResponse(output, 401, @{@"error": @"Malformed Authorization header."});
        return;
    }
    
    NSString *token = parts[1];
    NSDictionary *payload = verifyJWT(token);
    if (!payload || !payload[@"email"]) {
        sendJSONResponse(output, 401, @{@"error": @"Invalid or expired token."});
        return;
    }
    
    NSString *email = payload[@"email"];
    if (users[email]) {
        [users removeObjectForKey:email];
        sendJSONResponse(output, 200, @{@"success": @YES});
    } else {
        sendJSONResponse(output, 400, @{@"success": @NO, @"error": @"User not found."});
    }
}

// Socket handler
void handleConnection(CFSocketNativeHandle socket) {
    NSInputStream *inputStream;
    NSOutputStream *outputStream;

    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    CFStreamCreatePairWithSocket(kCFAllocatorDefault, socket, &readStream, &writeStream);
    
    inputStream = (__bridge_transfer NSInputStream *)readStream;
    outputStream = (__bridge_transfer NSOutputStream *)writeStream;
    
    [inputStream open];
    [outputStream open];
    
    // Read request headers
    NSMutableString *headerString = [NSMutableString string];
    uint8_t buffer[1];
    NSInteger bytesRead;
    BOOL foundEnd = NO;
    
    while (!foundEnd && (bytesRead = [inputStream read:buffer maxLength:1]) > 0) {
        [headerString appendString:[[NSString alloc] initWithBytes:buffer length:bytesRead encoding:NSUTF8StringEncoding]];
        if ([headerString hasSuffix:@"\r\n\r\n"]) {
            foundEnd = YES;
        }
    }
    
    // Parse request line and headers
    NSArray *lines = [headerString componentsSeparatedByString:@"\r\n"];
    if (lines.count < 2) {
        sendJSONResponse(outputStream, 400, @{@"error": @"Invalid request"});
        // Close and return (instead of goto)
        [inputStream close];
        [outputStream close];
        close(socket);
        return;
    }
    
    NSArray *requestLine = [lines[0] componentsSeparatedByString:@" "];
    if (requestLine.count < 2) {
        sendJSONResponse(outputStream, 400, @{@"error": @"Invalid request line"});
        // Close and return (instead of goto)
        [inputStream close];
        [outputStream close];
        close(socket);
        return;
    }
    
    NSString *method = requestLine[0];
    NSString *path   = requestLine[1];
    
    // Now define headers
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *line = lines[i];
        // Stop if we hit an empty line
        if ([line isEqualToString:@""]) break;
        
        NSArray *headerParts = [line componentsSeparatedByString:@": "];
        if (headerParts.count == 2) {
            headers[headerParts[0]] = headerParts[1];
        }
    }
    
    // Grab content length (if any)
    NSUInteger contentLength = 0;
    if (headers[@"Content-Length"]) {
        contentLength = [headers[@"Content-Length"] integerValue];
    }
    
    // Route request
    if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/register"]) {
        handleRegister(inputStream, outputStream, contentLength);
    } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/login"]) {
        handleLogin(inputStream, outputStream, contentLength);
    } else if ([method isEqualToString:@"DELETE"] && [path isEqualToString:@"/delete"]) {
        handleDelete(inputStream, outputStream, headers);
    } else {
        sendJSONResponse(outputStream, 404, @{@"error": @"Not found"});
    }
    
    // Normal cleanup at the end of the function
    [inputStream close];
    [outputStream close];
    close(socket);
}

void socketCallback(CFSocketRef socket, CFSocketCallBackType type, CFDataRef address, const void *data, void *info) {
    if (type == kCFSocketAcceptCallBack) {
        CFSocketNativeHandle nativeSocket = *(CFSocketNativeHandle *)data;
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            handleConnection(nativeSocket);
        });
    }
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Initialize user storage
        users = [NSMutableDictionary dictionary];
        
        // Create socket
        CFSocketRef socket = CFSocketCreate(
            kCFAllocatorDefault,
            PF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            kCFSocketAcceptCallBack,
            socketCallback,
            NULL
        );
        
        if (!socket) {
            NSLog(@"Failed to create socket");
            return 1;
        }
        
        int yes = 1;
        setsockopt(CFSocketGetNative(socket), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_len = sizeof(addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(kPort);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        
        CFDataRef addressData = CFDataCreate(
            kCFAllocatorDefault,
            (UInt8 *)&addr,
            sizeof(addr)
        );
        
        if (CFSocketSetAddress(socket, addressData) != kCFSocketSuccess) {
            NSLog(@"Failed to bind to port %lu", (unsigned long)kPort);
            CFRelease(addressData);
            CFRelease(socket);
            return 1;
        }
        
        CFRelease(addressData);
        
        CFRunLoopSourceRef runLoopSource = CFSocketCreateRunLoopSource(
            kCFAllocatorDefault,
            socket,
            0
        );
        
        CFRunLoopAddSource(
            CFRunLoopGetCurrent(),
            runLoopSource,
            kCFRunLoopCommonModes
        );
        
        NSLog(@"Server running on port %lu", (unsigned long)kPort);
        
        CFRunLoopRun();
        
        CFRelease(runLoopSource);
        CFRelease(socket);
    }
    return 0;
}
