import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeURL from "node:url";
import * as NodeChildProcess from "node:child_process";

const root = NodePath.resolve(NodePath.dirname(NodeURL.fileURLToPath(import.meta.url)), "../../..");
const temporary = NodePath.join(root, "integrations/confidential-vm/.test-run/mobile-spki");
NodeFS.mkdirSync(temporary, { recursive: true });
const main = NodePath.join(temporary, "main.mm");
const binary = NodePath.join(temporary, "spki-test");
NodeFS.writeFileSync(
  main,
  `#import <Foundation/Foundation.h>
#import "T3AttestationPins.h"
int main() { @autoreleasepool {
  NSData *data = [[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
  NSString *digest = T3AttestationSPKIHash(data);
  if (!digest) return 2;
  printf("%s", digest.UTF8String); return 0;
} }
`,
);
const native = NodePath.join(root, "apps/mobile/modules/t3-attestation/ios");
NodeChildProcess.execFileSync("xcrun", [
  "clang++",
  "-fobjc-arc",
  "-framework",
  "Foundation",
  "-framework",
  "Security",
  "-I",
  native,
  NodePath.join(native, "T3CertificateSPKI.mm"),
  main,
  "-o",
  binary,
]);

for (const algorithm of ["ec", "rsa"]) {
  NodeTest.test(`native SPKI matches ${algorithm} certificate DER, not the legacy raw key`, () => {
    const { privateKey } =
      algorithm === "ec"
        ? NodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
        : NodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const certificate = NodeChildProcess.execFileSync(
      "/usr/bin/openssl",
      ["req", "-new", "-x509", "-key", "/dev/stdin", "-subj", "/CN=fixture.invalid", "-days", "1"],
      {
        input: privateKey.export({ type: "pkcs8", format: "pem" }),
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    const x509 = new NodeCrypto.X509Certificate(certificate);
    const expected = NodeCrypto.createHash("sha256")
      .update(x509.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    NodeAssert.equal(
      NodeChildProcess.execFileSync(binary, [], { input: x509.raw, encoding: "utf8" }),
      expected,
    );
    NodeAssert.equal(
      NodeChildProcess.spawnSync(binary, [], { input: Buffer.concat([x509.raw, Buffer.from([0])]) })
        .status,
      2,
    );
  });
}
NodeTest.test("malformed DER does not produce a key hash", () => {
  for (const input of [
    Buffer.alloc(0),
    Buffer.from([0x30, 0x80]),
    Buffer.from([0x30, 0x85, 0xff]),
    Buffer.alloc(65537),
  ]) {
    NodeAssert.equal(NodeChildProcess.spawnSync(binary, [], { input }).status, 2);
  }
});
