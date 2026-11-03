import ExpoModulesCore
import Foundation
import LocalAuthentication

public final class T3AttestationModule: Module {
  private var authentication: LAContext?

  public func definition() -> ModuleDefinition {
    Name("T3Attestation")
    Function("policy") { () -> [String: Any] in
      Bundle.main.object(forInfoDictionaryKey: "T3AttestationPolicy") as? [String: Any] ?? [:]
    }
    Function("transportProtected") { () -> Bool in
      T3AttestationTransportReady()
    }
    AsyncFunction("authenticateOwner") { (reason: String, promise: Promise) in
      guard !reason.isEmpty && reason.count <= 512 else {
        promise.resolve(false)
        return
      }
      DispatchQueue.main.async {
        guard self.authentication == nil else {
          promise.resolve(false)
          return
        }
        let context = LAContext()
        self.authentication = context
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
          self.authentication = nil
          promise.resolve(false)
          return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { accepted, _ in
          DispatchQueue.main.async {
            if self.authentication === context {
              self.authentication = nil
            }
            promise.resolve(accepted)
          }
        }
      }
    }
    Function("cancelAuthentication") {
      DispatchQueue.main.async {
        self.authentication?.invalidate()
        self.authentication = nil
      }
    }
    OnDestroy {
      DispatchQueue.main.async {
        self.authentication?.invalidate()
        self.authentication = nil
      }
    }
  }
}
