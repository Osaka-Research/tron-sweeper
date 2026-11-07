package com.harvest.tronsweep

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

data class SweeperConfig(
    val apiUrls: List<String>,
    val apiKey: String,
    val sourceSecretKey: String,
    val destAddress: String,
    val pollIntervalMs: Int,
    val feeReserveSun: Long,
    val proxy: ProxyConfig = ProxyConfig(ProxyType.NONE, "", 0, "", "")
)

/** Everything here - especially the secret key - lives only in Android-Keystore-backed
 * EncryptedSharedPreferences, never plain SharedPreferences, never logged. */
object WalletConfigStore {
    private const val FILE = "tron_sweeper_secure_config"

    private const val KEY_API_URLS = "api_urls"
    private const val KEY_API_KEY = "api_key"
    private const val KEY_SECRET = "source_secret_key"
    private const val KEY_DEST = "dest_address"
    private const val KEY_POLL_MS = "poll_interval_ms"
    private const val KEY_FEE_RESERVE = "fee_reserve_sun"
    private const val KEY_PROXY_TYPE = "proxy_type"
    private const val KEY_PROXY_HOST = "proxy_host"
    private const val KEY_PROXY_PORT = "proxy_port"
    private const val KEY_PROXY_USER = "proxy_username"
    private const val KEY_PROXY_PASS = "proxy_password"

    private fun prefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        FILE,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun save(context: Context, config: SweeperConfig) {
        prefs(context).edit()
            .putString(KEY_API_URLS, config.apiUrls.joinToString("\n"))
            .putString(KEY_API_KEY, config.apiKey)
            .putString(KEY_SECRET, config.sourceSecretKey)
            .putString(KEY_DEST, config.destAddress)
            .putInt(KEY_POLL_MS, config.pollIntervalMs)
            .putLong(KEY_FEE_RESERVE, config.feeReserveSun)
            .putString(KEY_PROXY_TYPE, config.proxy.type.name)
            .putString(KEY_PROXY_HOST, config.proxy.host)
            .putInt(KEY_PROXY_PORT, config.proxy.port)
            .putString(KEY_PROXY_USER, config.proxy.username)
            .putString(KEY_PROXY_PASS, config.proxy.password)
            .apply()
    }

    fun load(context: Context): SweeperConfig? {
        val p = prefs(context)
        val secret = p.getString(KEY_SECRET, null) ?: return null
        val dest = p.getString(KEY_DEST, null) ?: return null
        val apiRaw = p.getString(KEY_API_URLS, "") ?: ""
        val apiUrls = apiRaw.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        if (apiUrls.isEmpty()) return null
        val proxyType = try {
            ProxyType.valueOf(p.getString(KEY_PROXY_TYPE, ProxyType.NONE.name) ?: ProxyType.NONE.name)
        } catch (_: Exception) {
            ProxyType.NONE
        }
        return SweeperConfig(
            apiUrls = apiUrls,
            apiKey = p.getString(KEY_API_KEY, "") ?: "",
            sourceSecretKey = secret,
            destAddress = dest,
            pollIntervalMs = p.getInt(KEY_POLL_MS, 800),
            feeReserveSun = p.getLong(KEY_FEE_RESERVE, 2_000_000),
            proxy = ProxyConfig(
                type = proxyType,
                host = p.getString(KEY_PROXY_HOST, "") ?: "",
                port = p.getInt(KEY_PROXY_PORT, 0),
                username = p.getString(KEY_PROXY_USER, "") ?: "",
                password = p.getString(KEY_PROXY_PASS, "") ?: ""
            )
        )
    }
}
