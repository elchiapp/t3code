#import "T3AttestationPins.h"
#import <CommonCrypto/CommonDigest.h>
#import <React/RCTWebSocketModule.h>
#import <React/RCTHTTPRequestHandler.h>
#import <SocketRocket/SRWebSocket.h>
#import <SocketRocket/SRSecurityPolicy.h>

static BOOL installed = NO;
static NSDictionary *configuration;

@interface T3AttestedSocketPolicy : SRSecurityPolicy
@end
@implementation T3AttestedSocketPolicy
- (BOOL)evaluateServerTrust:(SecTrustRef)trust forDomain:(NSString *)domain {
  if (!installed || !trust || ![domain isEqualToString:configuration[@"hostname"]]) return NO;
  SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)domain);
  OSStatus configured = SecTrustSetPolicies(trust, policy); CFRelease(policy);
  if (configured != errSecSuccess || !SecTrustEvaluateWithError(trust, NULL)) return NO;
  CFArrayRef chain = SecTrustCopyCertificateChain(trust);
  if (!chain || CFArrayGetCount(chain) == 0) { if (chain) CFRelease(chain); return NO; }
  SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(chain, 0);
  NSData *der = CFBridgingRelease(SecCertificateCopyData(leaf));
  NSString *hash = T3AttestationSPKIHash(der); CFRelease(chain);
  return hash != nil && [hash isEqualToString:configuration[@"tlsSpkiSha256"]];
}
@end

BOOL T3AttestationTransportReady(void) { return installed; }

__attribute__((constructor)) static void installT3AttestationTransport(void) {
  configuration = [NSBundle mainBundle].infoDictionary[@"T3AttestationPolicy"];
  if (![configuration isKindOfClass:[NSDictionary class]]) return;
  NSString *hostname = configuration[@"hostname"];
  NSString *pin = configuration[@"tlsSpkiBase64"];
  if (!hostname.length || !pin.length) return;
  NSDictionary *ats = [NSBundle mainBundle].infoDictionary[@"NSAppTransportSecurity"];
  NSArray *leaves = ats[@"NSPinnedDomains"][hostname][@"NSPinnedLeafIdentities"];
  BOOL found = NO;
  for (NSDictionary *identity in leaves) if ([identity[@"SPKI-SHA256-BASE64"] isEqualToString:pin]) found = YES;
  if (!hostname.length || !pin.length || !found || [ats[@"NSAllowsArbitraryLoads"] boolValue]) return;
  RCTSetCustomHTTPRequestInterceptor(^NSURLRequest *(NSURLRequest *request) {
    if (![request.URL.host isEqualToString:hostname] || ![request.URL.scheme isEqualToString:@"http"]) return nil;
    NSMutableURLRequest *protectedRequest = [request mutableCopy];
    NSString *proofURL = [configuration[@"proofOrigin"] stringByAppendingString:@"/proof"];
    if ([request.URL.absoluteString isEqualToString:proofURL] && [request.HTTPMethod isEqualToString:@"POST"]) {
      [protectedRequest setValue:nil forHTTPHeaderField:@"Origin"];
      [protectedRequest setValue:nil forHTTPHeaderField:@"Authorization"];
      [protectedRequest setValue:nil forHTTPHeaderField:@"Cookie"];
    } else {
      NSURLComponents *url = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
      url.scheme = @"https"; protectedRequest.URL = url.URL;
    }
    return protectedRequest;
  });
  RCTSetCustomSRWebSocketProvider(^SRWebSocket *(NSURLRequest *request) {
    if (![request.URL.host isEqualToString:hostname]) return nil;
    NSMutableURLRequest *protectedRequest = [request mutableCopy];
    if (![request.URL.scheme isEqualToString:@"wss"]) {
      NSURLComponents *url = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
      url.scheme = @"wss"; protectedRequest.URL = url.URL;
    }
    T3AttestedSocketPolicy *policy = [[T3AttestedSocketPolicy alloc] init];
    return [[SRWebSocket alloc] initWithURLRequest:protectedRequest protocols:nil securityPolicy:policy];
  });
  installed = YES;
}
