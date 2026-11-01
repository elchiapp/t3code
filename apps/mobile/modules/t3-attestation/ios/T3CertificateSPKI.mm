#import "T3AttestationPins.h"
#import <CommonCrypto/CommonDigest.h>

static BOOL readTLV(NSData *data, NSUInteger *offset, NSUInteger limit, uint8_t *tag, NSRange *whole, NSRange *content) {
  const uint8_t *bytes = (const uint8_t *)data.bytes;
  NSUInteger start = *offset;
  if (limit > data.length || start >= limit) return NO;
  *tag = bytes[(*offset)++];
  if (*offset >= limit) return NO;
  NSUInteger length = bytes[(*offset)++];
  if (length & 0x80) {
    NSUInteger count = length & 0x7f;
    if (count == 0 || count > 4 || count > limit - *offset) return NO;
    length = 0;
    for (NSUInteger i = 0; i < count; i++) length = (length << 8) | bytes[(*offset)++];
  }
  if (length > limit - *offset) return NO;
  *content = NSMakeRange(*offset, length);
  *offset += length;
  *whole = NSMakeRange(start, *offset - start);
  return YES;
}

NSString *T3AttestationSPKIHash(NSData *certificate) {
  if (certificate.length > 65536) return nil;
  NSUInteger offset = 0; uint8_t tag; NSRange whole, content;
  if (!readTLV(certificate, &offset, certificate.length, &tag, &whole, &content) || tag != 0x30 || offset != certificate.length) return nil;
  offset = content.location;
  if (!readTLV(certificate, &offset, NSMaxRange(content), &tag, &whole, &content) || tag != 0x30) return nil;
  NSUInteger limit = NSMaxRange(content); offset = content.location;
  if (offset >= limit) return nil;
  if (((const uint8_t *)certificate.bytes)[offset] == 0xa0 && !readTLV(certificate, &offset, limit, &tag, &whole, &content)) return nil;
  for (NSUInteger i = 0; i < 5; i++) if (!readTLV(certificate, &offset, limit, &tag, &whole, &content)) return nil;
  if (!readTLV(certificate, &offset, limit, &tag, &whole, &content) || tag != 0x30) return nil;
  NSData *spki = [certificate subdataWithRange:whole];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(spki.bytes, (CC_LONG)spki.length, digest);
  NSMutableString *hex = [NSMutableString string];
  for (NSUInteger i = 0; i < sizeof(digest); i++) [hex appendFormat:@"%02x", digest[i]];
  return hex;
}
