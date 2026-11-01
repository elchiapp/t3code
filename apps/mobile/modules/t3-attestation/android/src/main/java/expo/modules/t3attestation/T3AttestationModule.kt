package expo.modules.t3attestation

import com.facebook.react.modules.network.NetworkingModule
import com.facebook.react.modules.websocket.WebSocketModule
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import okhttp3.CertificatePinner
import org.json.JSONObject

class T3AttestationModule : Module() {
  private var ready = false
  private var policy = JSONObject()

  override fun definition() = ModuleDefinition {
    Name("T3Attestation")
    OnCreate {
      val context = appContext.reactContext ?: return@OnCreate
      val resource = context.resources.getIdentifier(
        "t3_attestation_policy",
        "raw",
        context.packageName
      )
      if (resource == 0) return@OnCreate
      policy =
        context.resources.openRawResource(resource).bufferedReader().use {
          JSONObject(it.readText())
        }
      val hostname = policy.getString("hostname")
      val pin = policy.getString("tlsSpkiBase64")
      require(hostname.isNotEmpty() && !hostname.contains('*'))
      val pinner = CertificatePinner.Builder().add(hostname, "sha256/$pin").build()
      NetworkingModule.setCustomClientBuilder { builder -> builder.certificatePinner(pinner) }
      WebSocketModule.setCustomClientBuilder { builder -> builder.certificatePinner(pinner) }
      ready = true
    }
    Function("policy") { policy.toString() }
    Function("transportProtected") { ready }
  }
}
