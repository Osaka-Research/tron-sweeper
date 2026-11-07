package com.harvest.tronsweep

import android.util.Base64
import java.net.InetSocketAddress
import java.net.Proxy

enum class ProxyType { NONE, HTTP, SOCKS }

data class ProxyConfig(
    val type: ProxyType,
    val host: String,
    val port: Int,
    val username: String,
    val password: String
) {
    fun toJavaProxy(): Proxy? {
        if (type == ProxyType.NONE || host.isBlank() || port <= 0) return null
        val kind = if (type == ProxyType.SOCKS) Proxy.Type.SOCKS else Proxy.Type.HTTP
        return Proxy(kind, InetSocketAddress(host, port))
    }

    fun basicAuthHeader(): String? {
        if (type != ProxyType.HTTP || username.isBlank()) return null
        val raw = "$username:$password".toByteArray()
        return "Basic " + Base64.encodeToString(raw, Base64.NO_WRAP)
    }
}
