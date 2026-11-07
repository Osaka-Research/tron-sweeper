package com.harvest.tronsweep

import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

data class CreatedTx(val raw: JSONObject, val txIdHex: String)

/** REST client for the handful of Tron full-node/TronGrid-style endpoints the sweeper needs. */
object TronApiClient {

    private fun post(apiBase: String, path: String, body: JSONObject, apiKey: String?, proxy: ProxyConfig?, timeoutMs: Int): JSONObject {
        val javaProxy = proxy?.toJavaProxy()
        val url = URL(apiBase.trimEnd('/') + path)
        val connection = if (javaProxy != null) url.openConnection(javaProxy) else url.openConnection()
        val conn = (connection as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            if (!apiKey.isNullOrBlank()) setRequestProperty("TRON-PRO-API-KEY", apiKey)
            proxy?.basicAuthHeader()?.let { setRequestProperty("Proxy-Authorization", it) }
            doOutput = true
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
        }
        try {
            OutputStreamWriter(conn.outputStream).use { it.write(body.toString()) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = BufferedReader(InputStreamReader(stream)).use { it.readText() }
            if (text.isBlank()) return JSONObject()
            return JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }

    /** Balance in sun (1 TRX = 1_000_000 sun). 0 if the account has never been activated/funded. */
    fun getBalanceSun(apiBase: String, addressBase58: String, apiKey: String?, proxy: ProxyConfig?, timeoutMs: Int = 4000): Long {
        val body = JSONObject().apply {
            put("address", addressBase58)
            put("visible", true)
        }
        val root = post(apiBase, "/wallet/getaccount", body, apiKey, proxy, timeoutMs)
        return root.optLong("balance", 0L)
    }

    fun createTransferTransaction(
        apiBase: String,
        fromBase58: String,
        toBase58: String,
        amountSun: Long,
        apiKey: String?,
        proxy: ProxyConfig?,
        timeoutMs: Int = 6000
    ): CreatedTx {
        val body = JSONObject().apply {
            put("owner_address", fromBase58)
            put("to_address", toBase58)
            put("amount", amountSun)
            put("visible", true)
        }
        val root = post(apiBase, "/wallet/createtransaction", body, apiKey, proxy, timeoutMs)
        if (!root.has("txID")) {
            throw RuntimeException("createtransaction failed: ${root.optString("Error", root.toString())}")
        }
        return CreatedTx(root, root.getString("txID"))
    }

    /** Submits a transaction object with the "signature" field filled in; returns the broadcast txid. */
    fun broadcastTransaction(apiBase: String, signedTx: JSONObject, apiKey: String?, proxy: ProxyConfig?, timeoutMs: Int = 8000): String {
        val root = post(apiBase, "/wallet/broadcasttransaction", signedTx, apiKey, proxy, timeoutMs)
        if (root.optBoolean("result", false)) {
            return root.optString("txid", signedTx.optString("txID"))
        }
        throw RuntimeException("broadcast failed: ${root.optString("message", root.toString())}")
    }
}
