// Native device operations for the Linux iMessage engine. Build on macOS.
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <unistd.h>

static void fail(NSString *message) {
    fprintf(stderr, "%s\n", message.UTF8String);
    exit(1);
}

static NSData *run(NSString *program, NSArray<NSString *> *arguments, NSData *input) {
    NSTask *task = [NSTask new];
    task.launchPath = program;
    task.arguments = arguments;
    NSPipe *output = [NSPipe pipe];
    task.standardOutput = output;
    NSPipe *source = input ? [NSPipe pipe] : nil;
    task.standardInput = source ? (id)source : [NSFileHandle fileHandleWithNullDevice];
    @try {
        [task launch];
    } @catch (NSException *exception) {
        fail(@"Could not start a macOS system tool");
    }
    if (source) {
        [source.fileHandleForWriting writeData:input];
        [source.fileHandleForWriting closeFile];
    }
    NSData *bytes = [output.fileHandleForReading readDataToEndOfFile];
    [task waitUntilExit];
    if (task.terminationStatus != 0 || !bytes.length) fail(@"A macOS system tool failed");
    return bytes;
}

static id plist(NSData *bytes) {
    return [NSPropertyListSerialization propertyListWithData:bytes options:0 format:NULL error:NULL];
}

static NSString *stringValue(id value) {
    if ([value isKindOfClass:[NSString class]]) return value;
    if ([value isKindOfClass:[NSData class]]) {
        const uint8_t *bytes = [value bytes];
        NSUInteger size = [value length];
        while (size && bytes[size - 1] == 0) --size;
        return [[NSString alloc] initWithBytes:bytes length:size encoding:NSUTF8StringEncoding];
    }
    return nil;
}

static NSDictionary *hardware(void) {
    id data = plist(run(@"/usr/sbin/ioreg", @[@"-a", @"-r", @"-d", @"1", @"-c", @"IOPlatformExpertDevice"], nil));
    id platform = [data isKindOfClass:[NSArray class]] ? [data firstObject] : nil;
    if (![platform isKindOfClass:[NSDictionary class]]) fail(@"Could not read the Mac hardware identity");
    NSString *model = stringValue(platform[@"model"]);
    NSString *serial = stringValue(platform[@"IOPlatformSerialNumber"]);
    NSString *uuid = stringValue(platform[@"IOPlatformUUID"]);
    if (!model.length || !serial.length || ![[NSUUID alloc] initWithUUIDString:uuid ?: @""])
        fail(@"The Mac did not report a model, serial number, and hardware UUID");
    NSDictionary *version = [NSDictionary dictionaryWithContentsOfFile:
        @"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *os = stringValue(version[@"ProductVersion"]);
    NSString *build = stringValue(version[@"ProductBuildVersion"]);
    NSString *name = [NSHost currentHost].localizedName;
    if (!os.length || !build.length) fail(@"Could not determine the macOS version");
    return @{@"model": model, @"serial": serial, @"uuid": uuid, @"os-version": os,
             @"build-version": build, @"device-name": name.length ? name : @"Mac"};
}

static void emit(NSData *bytes) {
    if (!bytes.length) fail(@"The device operation returned no data");
    [[NSFileHandle fileHandleWithStandardOutput] writeData:bytes];
}

static void emitJSON(NSDictionary *object) {
    emit([NSJSONSerialization dataWithJSONObject:object options:0 error:NULL]);
}

static id objectProperty(id target, const char *name) {
    SEL selector = sel_registerName(name);
    if (![target respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(target, selector);
}

static void anisette(void) {
    dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_NOW);
    dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_NOW);
    Class aos = NSClassFromString(@"AOSUtilities");
    SEL otp = sel_registerName("retrieveOTPHeadersForDSID:");
    if (![aos respondsToSelector:otp]) fail(@"AOSKit is unavailable on this Mac");
    NSDictionary *headers = ((id (*)(id, SEL, id))objc_msgSend)(aos, otp, @"-2");
    if (![headers isKindOfClass:[NSDictionary class]]) fail(@"AOSKit returned invalid Anisette headers");
    id device = objectProperty(NSClassFromString(@"AKDevice"), "currentDevice");
    NSDictionary *computer = hardware();
    NSString *code = stringValue(headers[@"X-Apple-MD"]);
    NSString *machine = stringValue(headers[@"X-Apple-MD-M"]);
    NSString *routing = stringValue(headers[@"X-Apple-MD-RINFO"]);
    NSString *local = stringValue(objectProperty(device, "localUserUUID"));
    NSString *identifier = stringValue(objectProperty(device, "uniqueDeviceIdentifier"));
    NSString *description = stringValue(objectProperty(device, "serverFriendlyDescription"));
    if (!code.length || !machine.length || !local.length || !identifier.length || !description.length)
        fail(@"macOS could not supply Anisette for this device");
    NSDateFormatter *clock = [NSDateFormatter new];
    clock.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    clock.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    clock.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
    emitJSON(@{
        @"X-Apple-I-MD": code, @"X-Apple-I-MD-M": machine, @"X-Apple-I-MD-LU": local,
        @"X-Apple-I-MD-RINFO": routing ?: @"17106176", @"X-Mme-Device-Id": identifier,
        @"X-Apple-I-Client-Time": [clock stringFromDate:[NSDate date]],
        @"X-Mme-Client-Info": description, @"X-Apple-I-SRL-NO": computer[@"serial"],
        @"X-Apple-I-TimeZone": @"UTC", @"User-Agent": @"akd/1.0",
    });
}

#if defined(__x86_64__)
static BOOL isElCapitan(void) {
    NSOperatingSystemVersion version = [NSProcessInfo processInfo].operatingSystemVersion;
    return version.majorVersion == 10 && version.minorVersion == 11;
}
#endif

static BOOL matchesSystemBinary(const char *path, NSUInteger size, const unsigned char *expected) {
    NSData *image = [NSData dataWithContentsOfFile:@(path) options:NSDataReadingMappedIfSafe error:NULL];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    return image.length == size
        && CC_SHA256(image.bytes, (CC_LONG)image.length, digest)
        && memcmp(digest, expected, sizeof(digest)) == 0;
}

typedef int (*ActivationSigner)(const void *, int, void *, unsigned int *, void *, unsigned int *);

static ActivationSigner pushSigner(void) {
    const char *path = "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd";
    const unsigned char bigSur[CC_SHA256_DIGEST_LENGTH] = {
        0x0f, 0x22, 0xcb, 0xbd, 0x17, 0xc0, 0xa5, 0x5b, 0x2d, 0xc5, 0xff, 0xd0, 0xed, 0xa4, 0x84, 0x79,
        0x0c, 0x3b, 0x86, 0x02, 0xce, 0x39, 0x88, 0x32, 0xeb, 0xf7, 0xc2, 0xcd, 0x40, 0x88, 0x02, 0x57,
    };
    uintptr_t offset = 0;
#if defined(__x86_64__)
    const unsigned char elCapitan[CC_SHA256_DIGEST_LENGTH] = {
        0xaf, 0xe1, 0x44, 0x52, 0x44, 0x2c, 0xca, 0xb6, 0x59, 0x85, 0xe0, 0xc8, 0x85, 0x79, 0xda, 0x1c,
        0x4a, 0xfd, 0x10, 0xe5, 0xa7, 0x1c, 0xa9, 0x89, 0xe2, 0x2b, 0xc5, 0x57, 0x29, 0x6e, 0x30, 0x83,
    };
    if (matchesSystemBinary(path, 1032992, elCapitan)) offset = 0x5cb90;
    if (matchesSystemBinary(path, 2900624, bigSur)) offset = 0x9cec0;
#elif defined(__arm64__)
    if (matchesSystemBinary(path, 2900624, bigSur)) offset = 0xa8308;
#endif
    if (!offset) return NULL;
    void *handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
    const void *header = handle ? dlsym(handle, "_mh_execute_header") : NULL;
    return header ? (ActivationSigner)((uintptr_t)header + offset) : NULL;
}

static void systemActivationSign(ActivationSigner sign, NSData *payload) {
    // apsd signs the ASN.1 SHA-1 DigestInfo for the activation plist.
    unsigned char digestInfo[] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    CC_SHA1(payload.bytes, (CC_LONG)payload.length, digestInfo + sizeof(digestInfo) - CC_SHA1_DIGEST_LENGTH);
    unsigned char signature[256] = {0}, certificates[4000] = {0};
    unsigned int signatureSize = sizeof(signature), certificateSize = sizeof(certificates);
    sign(digestInfo, sizeof(digestInfo), signature, &signatureSize, certificates, &certificateSize);
    if (!signatureSize || signatureSize > sizeof(signature) || !certificateSize
        || certificateSize > sizeof(certificates) || certificates[0] != 0x30)
        fail(@"macOS could not sign the push activation request");

    emitJSON(@{@"certificate-chain": [[NSData dataWithBytes:certificates length:certificateSize]
                                            base64EncodedStringWithOptions:0],
               @"signature": [[NSData dataWithBytes:signature length:signatureSize]
                                    base64EncodedStringWithOptions:0]});
}

static NSString *activationCredentials(NSString **keyPath, NSData **certificateChain) {
    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:
        @"Library/Application Support/LinuxMessages"];
    NSString *key = [directory stringByAppendingPathComponent:@"activation-key.pem"];
    NSString *chain = [directory stringByAppendingPathComponent:@"activation-chain.pem"];
    struct stat meta;
    if (lstat(key.fileSystemRepresentation, &meta) || !S_ISREG(meta.st_mode)
        || meta.st_uid != getuid() || (meta.st_mode & 077) || meta.st_size <= 0 || meta.st_size > 32768)
        return @"missing-signing-key";
    if (lstat(chain.fileSystemRepresentation, &meta) || !S_ISREG(meta.st_mode)
        || meta.st_size <= 0 || meta.st_size > 32768)
        return @"missing-certificate-chain";
    NSData *certificates = [NSData dataWithContentsOfFile:chain];
    if (!certificates.length || certificates.length > 32768) return @"missing-certificate-chain";
    if (keyPath) *keyPath = key;
    if (certificateChain) *certificateChain = certificates;
    return nil;
}

static NSString *activationStatus(void) {
    NSString *error = activationCredentials(NULL, NULL);
    return !error || pushSigner() ? @"ready" : error;
}

static void activationSign(void) {
    NSFileHandle *input = [NSFileHandle fileHandleWithStandardInput];
    NSMutableData *payload = [NSMutableData data];
    for (;;) {
        NSData *chunk = [input readDataOfLength:4096];
        if (!chunk.length) break;
        [payload appendData:chunk];
        if (payload.length > 65536) fail(@"Invalid push activation request size");
    }
    if (!payload.length) fail(@"The activation request was empty");
    id request = plist(payload);
    NSDictionary *computer = hardware();
    if (![request isKindOfClass:[NSDictionary class]]
        || ![request[@"DeviceClass"] isEqual:@"MacOS"] || ![request[@"ActivationState"] isEqual:@"Unactivated"]
        || ![request[@"ProductType"] isEqual:computer[@"model"]]
        || ![request[@"SerialNumber"] isEqual:computer[@"serial"]]
        || ![request[@"ProductVersion"] isEqual:computer[@"os-version"]]
        || ![request[@"BuildVersion"] isEqual:computer[@"build-version"]]
        || ![request[@"UniqueDeviceID"] isEqual:[computer[@"uuid"] uppercaseString]]
        || ![request[@"DeviceCertRequest"] isKindOfClass:[NSData class]]
        || ![stringValue(request[@"DeviceCertRequest"]) hasPrefix:@"-----BEGIN CERTIFICATE REQUEST-----"])
        fail(@"The activation request does not match this Mac");

    NSString *key = nil;
    NSData *certificates = nil;
    NSString *error = activationCredentials(&key, &certificates);
    if (error) {
        ActivationSigner signer = pushSigner();
        if (!signer) fail(error);
        systemActivationSign(signer, payload);
        return;
    }
    NSData *signature = run(@"/usr/bin/openssl", @[@"dgst", @"-sha1", @"-sign", key], payload);
    emitJSON(@{@"certificate-chain": [certificates base64EncodedStringWithOptions:0],
               @"signature": [signature base64EncodedStringWithOptions:0]});
}

@interface NoRedirect : NSObject <NSURLSessionTaskDelegate>
@end
@implementation NoRedirect
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)newRequest
    completionHandler:(void (^)(NSURLRequest *))completionHandler {
    completionHandler(nil);
}
@end

static NSDictionary *appleRequest(NSString *endpoint, NSData *payload) {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:endpoint]];
    request.timeoutInterval = 17.;
    if (payload) {
        request.HTTPMethod = @"POST";
        request.HTTPBody = payload;
        [request setValue:@"application/x-apple-plist" forHTTPHeaderField:@"Content-Type"];
    }
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                        delegate:[NoRedirect new] delegateQueue:nil];
    dispatch_semaphore_t ready = dispatch_semaphore_create(0);
    __block NSData *body = nil;
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:
        ^(NSData *data, NSURLResponse *response, NSError *error) {
            if (!error && [response isKindOfClass:[NSHTTPURLResponse class]] &&
                ((NSHTTPURLResponse *)response).statusCode == 200 && data.length <= 262144)
                body = data;
            dispatch_semaphore_signal(ready);
        }];
    [task resume];
    if (dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 19 * NSEC_PER_SEC)) != 0) {
        [session invalidateAndCancel];
        fail(@"Apple device validation timed out");
    }
    [session finishTasksAndInvalidate];
    id decoded = body ? plist(body) : nil;
    if (![decoded isKindOfClass:[NSDictionary class]]) fail(@"Apple returned an invalid device validation response");
    return decoded;
}

static NSData *dataOperation(id context, SEL operation, NSData *argument) {
    NSError *error = nil;
    id result = ((id (*)(id, SEL, id, NSError *__autoreleasing *))objc_msgSend)(context, operation, argument, &error);
    return [result isKindOfClass:[NSData class]] ? result : nil;
}

static NSData *validationSession(NSData *challenge) {
    NSData *request = [NSPropertyListSerialization dataWithPropertyList:@{@"session-info-request": challenge}
                                          format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    NSDictionary *reply = appleRequest(@"https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation", request);
    NSData *session = reply[@"session-info"];
    id status = reply[@"status"];
    if ((status && (![status respondsToSelector:@selector(integerValue)] || [status integerValue] != 0))
        || ![session isKindOfClass:[NSData class]] || !session.length)
        fail(@"Apple rejected the Mac validation challenge");
    return session;
}

#if defined(__x86_64__)
static const char *legacyIDSPath =
    "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd";

static BOOL hasLegacyIDS(void) {
    // OS X 10.11.6 Combo Update: verify the complete executable before using its private entry points.
    const unsigned char expected[CC_SHA256_DIGEST_LENGTH] = {
        0xac, 0x48, 0x72, 0x38, 0xa2, 0x50, 0xc4, 0x89, 0xdd, 0xd4, 0x0b, 0x26, 0xf8, 0x82, 0x81, 0xcb,
        0x74, 0x98, 0x73, 0x58, 0x25, 0xc9, 0x4a, 0x8e, 0x4a, 0xf5, 0x95, 0x85, 0x32, 0x08, 0x72, 0x34,
    };
    return matchesSystemBinary(legacyIDSPath, 5039040, expected);
}

static NSData *legacyValidation(NSData *certificate) {
    if (!hasLegacyIDS()) fail(@"This El Capitan identityservicesd build is unsupported");

    void *handle = dlopen(legacyIDSPath, RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
    if (!handle) fail(@"Could not load the El Capitan validation framework");
    const uint8_t *reference = dlsym(handle, "IDSOpenSocketOptionAccountKey");
    if (!reference) fail(@"Could not locate the El Capitan validation routines");
    uintptr_t base = (uintptr_t)reference - 0x43efd0;

    int (*initialize)(const void *, int, void **, void **, int *) = (void *)(base + 0x1f1620);
    int (*establish)(void *, const void *, int) = (void *)(base + 0x1f1640);
    int (*sign)(void *, const void *, int, void **, int *) = (void *)(base + 0x1f1660);
    int (*releaseBytes)(void *) = (void *)(base + 0x1f1680);
    int (*releaseContext)(void *) = (void *)(base + 0x1f16a0);
    if (initialize(NULL, 0, NULL, NULL, NULL) != -44023)
        fail(@"El Capitan rejected the validation interface check");

    void *context = NULL, *bytes = NULL;
    int length = 0;
    if (initialize(certificate.bytes, (int)certificate.length, &context, &bytes, &length) != 0
        || !context || !bytes || length <= 0 || length > 262144)
        fail(@"El Capitan could not create an Apple validation challenge");
    NSData *challenge = [NSData dataWithBytes:bytes length:(NSUInteger)length];
    releaseBytes(bytes);

    NSData *session = validationSession(challenge);
    if (establish(context, session.bytes, (int)session.length) != 0)
        fail(@"El Capitan rejected Apple's validation response");
    bytes = NULL;
    length = 0;
    if (sign(context, NULL, 0, &bytes, &length) != 0 || !bytes || length <= 0 || length > 65536)
        fail(@"El Capitan could not produce Apple validation data");
    NSData *signature = [NSData dataWithBytes:bytes length:(NSUInteger)length];
    releaseBytes(bytes);
    releaseContext(context);
    return signature;
}
#endif

static Class nativeValidationClass(void) {
    dlopen("/System/Library/PrivateFrameworks/AppleAccount.framework/AppleAccount", RTLD_NOW | RTLD_LOCAL);
    return NSClassFromString(@"AAAbsintheContext");
}

static NSString *validationStatus(void) {
#if defined(__x86_64__)
    if (isElCapitan()) return hasLegacyIDS() ? @"ready" : @"unsupported-el-capitan";
#endif
    return nativeValidationClass() ? @"ready" : @"no-native-validation";
}

static NSData *validationProof(void) {
    NSData *certificate = appleRequest(@"https://static.ess.apple.com/identity/validation/cert-1.0.plist", nil)[@"cert"];
    if (![certificate isKindOfClass:[NSData class]] || !certificate.length) fail(@"Apple omitted the device validation certificate");
#if defined(__x86_64__)
    if (isElCapitan()) return legacyValidation(certificate);
#endif
    Class type = nativeValidationClass();
    if (!type) fail(@"This macOS version lacks the native device validation context");

    // The private selectors vary by OS build. Check both argument types and the return type before dispatch.
    unsigned count = 0, objects = 0, booleans = 0;
    Method *methods = class_copyMethodList(type, &count);
    SEL pair[2] = {0}, establish = NULL;
    for (unsigned index = 0; index < count; ++index) {
        Method method = methods[index];
        SEL selector = method_getName(method);
        NSString *name = NSStringFromSelector(selector);
        if (![name hasSuffix:@":error:"] || method_getNumberOfArguments(method) != 4) continue;
        char input[16] = {0}, error[16] = {0}, result[16] = {0};
        method_getArgumentType(method, 2, input, sizeof(input));
        method_getArgumentType(method, 3, error, sizeof(error));
        method_getReturnType(method, result, sizeof(result));
        if (input[0] != '@' || error[0] != '^') continue;
        if (result[0] == '@') {
            if (objects < 2) pair[objects] = selector;
            ++objects;
        } else if (result[0] == 'B' || result[0] == 'c') {
            establish = selector;
            ++booleans;
        }
    }
    free(methods);
    if (objects != 2 || booleans != 1) fail(@"This macOS build uses an unsupported device validation interface");
    NSData *requestBytes = nil;
    id context = nil;
    SEL sign = NULL;
    for (unsigned index = 0; index < 2; ++index) {
        context = [[type alloc] init];
        requestBytes = dataOperation(context, pair[index], certificate);
        if (requestBytes.length) {
            sign = pair[1 - index];
            break;
        }
    }
    if (!sign) fail(@"The Mac could not create an Apple validation challenge");
    NSData *session = validationSession(requestBytes);
    NSError *error = nil;
    if (!((BOOL (*)(id, SEL, id, NSError *__autoreleasing *))objc_msgSend)(context, establish, session, &error))
        fail(@"The Mac rejected Apple's validation response");
    NSData *signature = dataOperation(context, sign, nil);
    if (!signature.length) fail(@"macOS could not produce the requested validation data");
    return signature;
}

static void exportLocal(NSString *output) {
    NSString *key = nil;
    NSData *certificates = nil;
    NSString *error = activationCredentials(&key, &certificates);
    if (error) fail(error);
    NSData *privateKey = run(@"/usr/bin/openssl", @[@"pkey", @"-in", key, @"-outform", @"DER"], nil);
    NSData *qualification = validationProof();
    NSData *registration = validationProof();
    if ([qualification isEqualToData:registration]) fail(@"Apple returned duplicate validation proofs");
    NSData *document = [NSPropertyListSerialization dataWithPropertyList:@{
        @"version": @1,
        @"computer": hardware(),
        @"qualification-data": qualification,
        @"registration-data": registration,
        @"activation": @{@"key": privateKey, @"chain": certificates},
    } format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    if (!document.length) fail(@"Could not create a local device profile");
    int fd = open(output.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) fail(@"The destination exists or could not be created");
    @try {
        NSFileHandle *file = [[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES];
        [file writeData:document];
        [file synchronizeFile];
        [file closeFile];
    } @catch (NSException *exception) {
        unlink(output.fileSystemRepresentation);
        fail(@"Could not write the local device profile");
    }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *operation = argc >= 2 ? [NSString stringWithUTF8String:argv[1]] : @"";
        if (argc == 3 && [operation isEqual:@"export-local"]) {
            exportLocal([NSString stringWithUTF8String:argv[2]]);
            return 0;
        }
        if (argc != 2) fail(@"Expected a device operation");
        if ([operation isEqual:@"describe"]) emitJSON(hardware());
        else if ([operation isEqual:@"anisette"]) anisette();
        else if ([operation isEqual:@"activation-status"])
            emit([activationStatus() dataUsingEncoding:NSUTF8StringEncoding]);
        else if ([operation isEqual:@"activation-sign"]) activationSign();
        else if ([operation isEqual:@"validation-status"])
            emit([validationStatus() dataUsingEncoding:NSUTF8StringEncoding]);
        else if ([operation isEqual:@"validation"]) emit([validationProof() base64EncodedDataWithOptions:0]);
        else fail(@"Expected describe, anisette, activation-sign, validation, or export-local FILE");
    }
    return 0;
}
