package com.example.vaultapp

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.ValueCallback
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewAssetLoader.AssetsPathHandler
import androidx.webkit.WebViewClientCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.ServiceWorkerClientCompat
import androidx.webkit.ServiceWorkerControllerCompat
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : androidx.fragment.app.FragmentActivity() {

    private lateinit var webView: WebView
    private var fileChooserCallback: ValueCallback<Array<Uri>>? = null
    private var pageLoaded = false

    private val KEY_ALIAS   = "vault_bio_key"
    private val PREFS_NAME  = "vault_prefs"
    private val PREF_ENC_PW = "enc_master_pw"
    private val PREF_ENC_IV = "enc_master_iv"

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val uris: Array<Uri>? = if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { arrayOf(it) }
        } else null
        fileChooserCallback?.onReceiveValue(uris)
        fileChooserCallback = null
    }

    // ── Keystore helpers ────────────────────────────────────────────────────

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(
                    KeyGenParameterSpec.Builder(KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build()
                )
                generateKey()
            }
        }
        return (keyStore.getKey(KEY_ALIAS, null) as SecretKey)
    }

    private fun encryptAndStore(pw: String) {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val encrypted = cipher.doFinal(pw.toByteArray(Charsets.UTF_8))
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                .putString(PREF_ENC_PW, Base64.encodeToString(encrypted, Base64.DEFAULT))
                .putString(PREF_ENC_IV, Base64.encodeToString(cipher.iv, Base64.DEFAULT))
                .apply()
        } catch (_: Exception) {}
    }

    private fun decryptStored(): String? {
        return try {
            val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val encPw = prefs.getString(PREF_ENC_PW, null) ?: return null
            val iv    = prefs.getString(PREF_ENC_IV, null) ?: return null
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(),
                GCMParameterSpec(128, Base64.decode(iv, Base64.DEFAULT)))
            String(cipher.doFinal(Base64.decode(encPw, Base64.DEFAULT)), Charsets.UTF_8)
        } catch (_: Exception) { null }
    }

    private fun clearStoredKey() {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
    }

    private fun hasStoredKey(): Boolean {
        return getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(PREF_ENC_PW, null) != null
    }

    private var isBiometricShowing = false
    private var vaultLocked = false

    // ── Biometric prompt ────────────────────────────────────────────────────

    private fun showBiometricPrompt() {
        val bm = BiometricManager.from(this)
        if (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            != BiometricManager.BIOMETRIC_SUCCESS) return
        if (isBiometricShowing) return

        isBiometricShowing = true
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    isBiometricShowing = false
                    vaultLocked = false
                    val pw = decryptStored() ?: return
                    val pwJson = JSONObject.quote(pw)
                    webView.evaluateJavascript("unlockWithPassword($pwJson);", null)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    isBiometricShowing = false
                }
                override fun onAuthenticationFailed() {
                    isBiometricShowing = false
                }
            }
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Vault")
            .setSubtitle("Use biometric to access your vault")
            .setNegativeButtonText("Use Password")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        prompt.authenticate(info)
    }

    // ── JS Bridge ───────────────────────────────────────────────────────────

    inner class AndroidBridge {

        @JavascriptInterface
        fun saveToDownloads(filename: String, content: String): String {
            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val values = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, filename)
                        put(MediaStore.Downloads.MIME_TYPE, "application/json")
                        put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    }
                    val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                        ?: return "Export failed: could not create file"
                    contentResolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) }
                    "Saved to Downloads/$filename"
                } else {
                    val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                    dir.mkdirs()
                    File(dir, filename).writeText(content)
                    "Saved to Downloads/$filename"
                }
            } catch (e: Exception) {
                "Export failed: ${e.message}"
            }
        }

        @JavascriptInterface
        fun notifyLocked() {
            // Called from JS lockApp() — vault just locked, trigger biometric
            vaultLocked = true
            ContextCompat.getMainExecutor(this@MainActivity).execute {
                if (hasStoredKey()) showBiometricPrompt()
            }
        }

        @JavascriptInterface
        fun storeMasterKey(pw: String) {
            vaultLocked = false
            encryptAndStore(pw)
        }

        @JavascriptInterface
        fun clearMasterKey() {
            clearStoredKey()
        }
    }

    // ── Activity lifecycle ──────────────────────────────────────────────────

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_main)
        webView = findViewById(R.id.webview)

        val assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", AssetsPathHandler(this))
            .build()

        val s = webView.settings
        s.javaScriptEnabled  = true
        s.domStorageEnabled  = true
        s.databaseEnabled    = true
        s.allowFileAccess    = false
        s.allowContentAccess = false
        s.setSupportZoom(false)

        webView.addJavascriptInterface(AndroidBridge(), "Android")

        webView.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                view: WebView,
                callback: ValueCallback<Array<Uri>>,
                params: FileChooserParams
            ): Boolean {
                fileChooserCallback?.onReceiveValue(null)
                fileChooserCallback = callback
                val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                    type = "application/json"
                    addCategory(Intent.CATEGORY_OPENABLE)
                }
                filePickerLauncher.launch(intent)
                return true
            }
        }

        webView.webViewClient = object : WebViewClientCompat() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest)
                = assetLoader.shouldInterceptRequest(request.url)

            override fun onPageFinished(view: WebView, url: String) {
                super.onPageFinished(view, url)
                pageLoaded = true
                if (hasStoredKey()) showBiometricPrompt()
            }

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val host = request.url.host ?: return true
                if (host == "appassets.androidplatform.net") return false
                startActivity(Intent(Intent.ACTION_VIEW, request.url))
                return true
            }
        }

        if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_BASIC_USAGE) &&
            WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_SHOULD_INTERCEPT_REQUEST)
        ) {
            val swController = ServiceWorkerControllerCompat.getInstance()
            swController.setServiceWorkerClient(object : ServiceWorkerClientCompat() {
                override fun shouldInterceptRequest(request: WebResourceRequest)
                    = assetLoader.shouldInterceptRequest(request.url)
            })
        }

        if (savedInstanceState == null) {
            webView.loadUrl("https://appassets.androidplatform.net/assets/index.html")
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // Fires when app regains focus after background or after biometric dialog dismisses
        if (hasFocus && pageLoaded && vaultLocked && hasStoredKey()) {
            showBiometricPrompt()
        }
    }

    override fun onPause() {
        super.onPause()
        if (pageLoaded && this::webView.isInitialized) {
            vaultLocked = true  // set immediately — don't wait for JS async chain
            webView.evaluateJavascript("if(typeof lockApp==='function')lockApp();", null)
        }
    }

    override fun onBackPressed() {
        if (this::webView.isInitialized && webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
}
