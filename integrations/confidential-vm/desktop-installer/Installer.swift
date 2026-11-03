import AppKit
import Foundation

final class InstallerDelegate: NSObject, NSApplicationDelegate {
  private var progress: NSWindow?
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.activate(ignoringOtherApps: true)
    let existing = NSWorkspace.shared.runningApplications.contains {
      ["io.elchiapp.t3attested.desktop", "io.elchiapp.t3code.attested.air", "io.elchiapp.t3-attested.air-launcher"].contains($0.bundleIdentifier ?? "")
    }
    if existing {
      show("Close T3 before installing", "Quit the existing T3 app, then open this installer again. Your accounts and conversations will stay in place.")
      NSApp.terminate(nil)
      return
    }
    let confirmation = NSAlert()
    confirmation.messageText = "Install T3 Attested?"
    confirmation.informativeText = "Installs the app in your Applications folder and its verification service for this account. No administrator password is needed. No accounts, chats, API keys or device approvals are imported. An older T3 Attested Air verification service is retired if present. New TEE builds still require your approval in T3."
    confirmation.addButton(withTitle: "Install")
    confirmation.addButton(withTitle: "Cancel")
    guard confirmation.runModal() == .alertFirstButtonReturn else { NSApp.terminate(nil); return }
    guard let resources = Bundle.main.resourceURL else { NSApp.terminate(nil); return }
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 450, height: 110), styleMask: [.titled], backing: .buffered, defer: false)
    window.title = "Installing T3 Attested"
    let label = NSTextField(labelWithString: "Installing the app and local verification service…")
    label.frame = NSRect(x: 24, y: 52, width: 410, height: 24)
    window.contentView?.addSubview(label)
    let indicator = NSProgressIndicator(frame: NSRect(x: 24, y: 22, width: 400, height: 18))
    indicator.style = .bar
    indicator.isIndeterminate = true
    indicator.startAnimation(nil)
    window.contentView?.addSubview(indicator)
    window.center()
    window.makeKeyAndOrderFront(nil)
    progress = window
    DispatchQueue.global(qos: .userInitiated).async {
      let process = Process()
      let output = Pipe()
      let errors = Pipe()
      let payload = resources.appendingPathComponent("payload")
      process.executableURL = payload.appendingPathComponent("runtime/node")
      process.arguments = [resources.appendingPathComponent("install.mjs").path, payload.path, FileManager.default.homeDirectoryForCurrentUser.path]
      process.standardOutput = output
      process.standardError = errors
      var result: [String: Any]?
      var failure = "The installer could not complete. Existing data and trust decisions were preserved."
      do {
        try process.run()
        process.waitUntilExit()
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        let errorBytes = errors.fileHandleForReading.readDataToEndOfFile()
        if process.terminationStatus == 0 {
          result = try JSONSerialization.jsonObject(with: bytes) as? [String: Any]
        } else if let message = String(data: errorBytes, encoding: .utf8), !message.isEmpty {
          failure = String(message.prefix(1500))
        }
      } catch { failure = error.localizedDescription }
      DispatchQueue.main.async {
        self.progress?.close()
        if let app = result?["app"] as? String {
          let ready = NSAlert()
          ready.messageText = "T3 Attested is installed"
          ready.informativeText = "Keep Tailscale connected. Open T3, add your environment and pair normally. Open the verification indicator → Review versions for exact-build approval. Verification checks and device authentication run on this Mac. No TEE update was approved by the installer."
          ready.addButton(withTitle: "Open T3 Attested")
          ready.addButton(withTitle: "Close")
          if ready.runModal() == .alertFirstButtonReturn { NSWorkspace.shared.open(URL(fileURLWithPath: app)) }
        } else { self.show("Installation stopped", failure) }
        NSApp.terminate(nil)
      }
    }
  }
  private func show(_ title: String, _ message: String) {
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = message
    alert.addButton(withTitle: "Close")
    alert.runModal()
  }
}
let app = NSApplication.shared
let delegate = InstallerDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
