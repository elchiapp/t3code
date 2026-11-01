import ExpoModulesCore
import Foundation

public final class T3AttestationModule: Module {
  public func definition() -> ModuleDefinition {
    Name("T3Attestation")
    Function("policy") { () -> [String: Any] in
      Bundle.main.object(forInfoDictionaryKey: "T3AttestationPolicy") as? [String: Any] ?? [:]
    }
    Function("transportProtected") { () -> Bool in
      T3AttestationTransportReady()
    }
  }
}
