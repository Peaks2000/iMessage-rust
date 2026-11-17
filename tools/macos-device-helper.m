// Native device operations for the Linux iMessage engine. Build on macOS.
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static void fail(NSString *message) {
    fprintf(stderr, "%s\n", message.UTF8String);
    exit(1);
}

static NSData *run(NSString *program, NSArray<NSString *> *arguments, NSData *input) {
    NSTask *task = [NSTask new];
    task.executableURL = [NSURL fileURLWithPath:program];
    task.arguments = arguments;
    NSPipe *output = [NSPipe pipe];
    task.standardOutput = output;
    NSPipe *source = input ? [NSPipe pipe] : nil;
    task.standardInput = source ? (id)source : [NSFileHandle fileHandleWithNullDevice];
    if (![task launchAndReturnError:NULL]) fail(@"Could not start a macOS system tool");
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

static NSString *trimmed(NSString *text) {
    return [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
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
    NSString *os = trimmed(stringValue(run(@"/usr/bin/sw_vers", @[@"-productVersion"], nil)));
    NSString *build = trimmed(stringValue(run(@"/usr/bin/sw_vers", @[@"-buildVersion"], nil)));
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
    NSString *code = stringValue(headers[@"X-Apple-MD"]);
    NSString *machine = stringValue(headers[@"X-Apple-MD-M"]);
    NSString *routing = stringValue(headers[@"X-Apple-MD-RINFO"]);
    NSString *local = stringValue(objectProperty(device, "localUserUUID"));
    NSString *identifier = stringValue(objectProperty(device, "uniqueDeviceIdentifier"));
    NSString *description = stringValue(objectProperty(device, "serverFriendlyDescription"));
    if (!code.length || !machine.length || !local.length || !identifier.length || !description.length)
        fail(@"macOS could not supply Anisette for this device");
    NSISO8601DateFormatter *clock = [NSISO8601DateFormatter new];
    NSDictionary *computer = hardware();
    emitJSON(@{
        @"X-Apple-I-MD": code, @"X-Apple-I-MD-M": machine, @"X-Apple-I-MD-LU": local,
        @"X-Apple-I-MD-RINFO": routing ?: @"17106176", @"X-Mme-Device-Id": identifier,
        @"X-Apple-I-Client-Time": [clock stringFromDate:[NSDate date]],
        @"X-Mme-Client-Info": description, @"X-Apple-I-SRL-NO": computer[@"serial"],
        @"X-Apple-I-TimeZone": @"UTC", @"User-Agent": @"akd/1.0",
    });
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

    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/LinuxMessages"];
    NSString *key = [directory stringByAppendingPathComponent:@"activation-key.pem"];
    NSString *chain = [directory stringByAppendingPathComponent:@"activation-chain.pem"];
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:key error:NULL];
    if (![attributes[NSFileType] isEqual:NSFileTypeRegular] ||
        ([attributes[NSFilePosixPermissions] unsignedIntValue] & 077) != 0)
        fail(@"Install an owner-only Apple activation signing key in LinuxMessages");
    NSData *certificates = [NSData dataWithContentsOfFile:chain];
    if (!certificates.length || certificates.length > 32768) fail(@"The Apple activation certificate chain is unavailable");
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

static void validation(void) {
    dlopen("/System/Library/PrivateFrameworks/AppleAccount.framework/AppleAccount", RTLD_NOW);
    Class type = NSClassFromString(@"AAAbsintheContext");
    if (!type) fail(@"This macOS version lacks the native device validation context");
    NSData *certificate = appleRequest(@"https://static.ess.apple.com/identity/validation/cert-1.0.plist", nil)[@"cert"];
    if (![certificate isKindOfClass:[NSData class]] || !certificate.length) fail(@"Apple omitted the device validation certificate");

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
    NSData *request = [NSPropertyListSerialization dataWithPropertyList:@{@"session-info-request": requestBytes}
                                          format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    NSDictionary *reply = appleRequest(@"https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation", request);
    NSData *session = reply[@"session-info"];
    id status = reply[@"status"];
    if ((status && (![status respondsToSelector:@selector(integerValue)] || [status integerValue] != 0))
        || ![session isKindOfClass:[NSData class]] || !session.length)
        fail(@"Apple rejected the Mac validation challenge");
    NSError *error = nil;
    if (!((BOOL (*)(id, SEL, id, NSError *__autoreleasing *))objc_msgSend)(context, establish, session, &error))
        fail(@"The Mac rejected Apple's validation response");
    NSData *signature = dataOperation(context, sign, nil);
    if (!signature.length) fail(@"macOS could not produce the requested validation data");
    emit([signature base64EncodedDataWithOptions:0]);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *operation = argc == 2 ? [NSString stringWithUTF8String:argv[1]] : @"";
        if ([operation isEqual:@"describe"]) emitJSON(hardware());
        else if ([operation isEqual:@"anisette"]) anisette();
        else if ([operation isEqual:@"activation-sign"]) activationSign();
        else if ([operation isEqual:@"validation"]) validation();
        else fail(@"Expected describe, anisette, activation-sign, or validation");
    }
    return 0;
}
