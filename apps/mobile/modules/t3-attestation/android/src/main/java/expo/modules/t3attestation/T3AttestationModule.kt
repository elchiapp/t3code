package expo.modules.t3attestation

import android.app.Activity
import android.app.KeyguardManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import com.facebook.react.modules.network.NetworkingModule
import com.facebook.react.modules.websocket.WebSocketModule
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.Promise
import okhttp3.CertificatePinner
import org.json.JSONObject

class T3AttestationModule : Module() {
  private var ready = false
  private var policy = JSONObject()
  private var authentication: CancellationSignal? = null
  private var credentialPromise: Promise? = null
  private val credentialRequestCode = 0x7433

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
    AsyncFunction("authenticateOwner") { reason: String, promise: Promise ->
      val activity = appContext.currentActivity
      if (activity == null || reason.isBlank() || reason.length > 512) {
        promise.resolve(false)
      } else activity.runOnUiThread {
        if (authentication != null || credentialPromise != null || activity.isFinishing || activity.isDestroyed) {
          promise.resolve(false)
          return@runOnUiThread
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
          val manager = activity.getSystemService(BiometricManager::class.java)
          if (manager?.canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            promise.resolve(false)
            return@runOnUiThread
          }
          val cancellation = CancellationSignal()
          authentication = cancellation
          val prompt = BiometricPrompt.Builder(activity)
            .setTitle("Approve reviewed T3 build")
            .setDescription(reason)
            .setAllowedAuthenticators(authenticators)
            .setConfirmationRequired(true)
            .build()
          prompt.authenticate(cancellation, activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
              override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (authentication === cancellation) authentication = null
                promise.resolve(!cancellation.isCanceled)
              }
              override fun onAuthenticationError(code: Int, message: CharSequence) {
                if (authentication === cancellation) authentication = null
                promise.resolve(false)
              }
            })
        } else {
          val manager = activity.getSystemService(KeyguardManager::class.java)
          val intent = if (manager?.isDeviceSecure == true)
            manager.createConfirmDeviceCredentialIntent("Approve reviewed T3 build", reason) else null
          if (intent == null) promise.resolve(false)
          else {
            credentialPromise = promise
            try { activity.startActivityForResult(intent, credentialRequestCode) }
            catch (_: Exception) { credentialPromise = null; promise.resolve(false) }
          }
        }
      }
    }
    OnActivityResult { _, result ->
      if (result.requestCode == credentialRequestCode) {
        val pending = credentialPromise
        credentialPromise = null
        pending?.resolve(result.resultCode == Activity.RESULT_OK)
      }
    }
    Function("cancelAuthentication") {
      authentication?.cancel()
      authentication = null
      credentialPromise?.resolve(false)
      credentialPromise = null
    }
    OnDestroy {
      authentication?.cancel()
      credentialPromise?.resolve(false)
      authentication = null
      credentialPromise = null
    }
  }
}
