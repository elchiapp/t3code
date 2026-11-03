import Foundation
import LocalAuthentication

guard CommandLine.arguments.count == 2 else { exit(3) }
let reason = CommandLine.arguments[1]
guard !reason.isEmpty && reason.count <= 512 else { exit(3) }
let context = LAContext()
var error: NSError?
guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { exit(3) }
context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { accepted, _ in
  exit(accepted ? 0 : 2)
}
RunLoop.main.run()
