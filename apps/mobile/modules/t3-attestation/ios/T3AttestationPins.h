#import <Foundation/Foundation.h>
#import <Security/Security.h>
#ifdef __cplusplus
extern "C" {
#endif
BOOL T3AttestationTransportReady(void);
NSString * _Nullable T3AttestationSPKIHash(NSData * _Nonnull certificate);
#ifdef __cplusplus
}
#endif
