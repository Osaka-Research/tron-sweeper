package com.harvest.tronsweep

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
        }

        val editApiUrls = findViewById<EditText>(R.id.edit_api_urls)
        val editApiKey = findViewById<EditText>(R.id.edit_api_key)
        val editSecret = findViewById<EditText>(R.id.edit_secret_key)
        val editDest = findViewById<EditText>(R.id.edit_dest_address)
        val editPoll = findViewById<EditText>(R.id.edit_poll_ms)
        val editFeeReserve = findViewById<EditText>(R.id.edit_fee_reserve)
        val txtDerived = findViewById<TextView>(R.id.txt_derived_address)
        val btnSave = findViewById<Button>(R.id.btn_save)
        val btnStart = findViewById<Button>(R.id.btn_start)
        val btnStop = findViewById<Button>(R.id.btn_stop)
        val txtStatus = findViewById<TextView>(R.id.txt_status)
        val txtLog = findViewById<TextView>(R.id.txt_log)

        val spinnerProxyType = findViewById<Spinner>(R.id.spinner_proxy_type)
        val editProxyHost = findViewById<EditText>(R.id.edit_proxy_host)
        val editProxyPort = findViewById<EditText>(R.id.edit_proxy_port)
        val editProxyUser = findViewById<EditText>(R.id.edit_proxy_user)
        val editProxyPass = findViewById<EditText>(R.id.edit_proxy_pass)

        val proxyTypes = ProxyType.values()
        spinnerProxyType.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, proxyTypes.map { it.name }
        )

        if (editApiUrls.text.isNullOrBlank()) editApiUrls.setText("https://api.trongrid.io")

        findViewById<Button>(R.id.btn_use_shasta).setOnClickListener {
            editApiUrls.setText("https://api.shasta.trongrid.io")
            txtStatus.text = "switched to Shasta testnet — claim test TRX manually, then the sweep loop will pick it up"
        }
        findViewById<Button>(R.id.btn_use_nile).setOnClickListener {
            editApiUrls.setText("https://nile.trongrid.io")
            txtStatus.text = "switched to Nile testnet — claim test TRX manually, then the sweep loop will pick it up"
        }
        findViewById<Button>(R.id.btn_open_shasta_faucet).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://shasta.tronex.io/")))
        }
        findViewById<Button>(R.id.btn_open_nile_faucet).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://nileex.io/join/getJoinPage")))
        }

        WalletConfigStore.load(this)?.let { cfg ->
            editApiUrls.setText(cfg.apiUrls.joinToString("\n"))
            editApiKey.setText(cfg.apiKey)
            editSecret.setText(cfg.sourceSecretKey)
            editDest.setText(cfg.destAddress)
            editPoll.setText(cfg.pollIntervalMs.toString())
            editFeeReserve.setText(cfg.feeReserveSun.toString())
            spinnerProxyType.setSelection(proxyTypes.indexOf(cfg.proxy.type).coerceAtLeast(0))
            editProxyHost.setText(cfg.proxy.host)
            if (cfg.proxy.port > 0) editProxyPort.setText(cfg.proxy.port.toString())
            editProxyUser.setText(cfg.proxy.username)
            editProxyPass.setText(cfg.proxy.password)
            tryShowDerivedAddress(cfg.sourceSecretKey, txtDerived)
        }

        editSecret.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) tryShowDerivedAddress(editSecret.text.toString(), txtDerived)
        }

        fun refreshStatus() {
            txtStatus.text = if (SweeperService.isRunning.get()) "status: RUNNING" else "status: stopped"
        }
        refreshStatus()

        SweepLog.setListener { lines -> runOnUiThread { txtLog.text = lines.joinToString("\n") } }

        btnSave.setOnClickListener {
            val apiUrls = editApiUrls.text.toString().split("\n").map { it.trim() }.filter { it.isNotEmpty() }
            val apiKey = editApiKey.text.toString().trim()
            val secret = editSecret.text.toString().trim()
            val dest = editDest.text.toString().trim()
            val pollMs = editPoll.text.toString().toIntOrNull() ?: 800
            val feeReserve = editFeeReserve.text.toString().toLongOrNull() ?: 2_000_000L

            if (apiUrls.isEmpty()) { txtStatus.text = "add at least one API URL"; return@setOnClickListener }
            if (secret.isEmpty()) { txtStatus.text = "paste the source wallet's secret key"; return@setOnClickListener }
            if (dest.isEmpty()) { txtStatus.text = "enter a destination address"; return@setOnClickListener }

            try {
                TronKeypair.parse(secret)
                Base58.decodeCheck(dest)
            } catch (e: Exception) {
                txtStatus.text = "config invalid: ${e.message}"
                return@setOnClickListener
            }

            val proxy = ProxyConfig(
                type = proxyTypes[spinnerProxyType.selectedItemPosition],
                host = editProxyHost.text.toString().trim(),
                port = editProxyPort.text.toString().toIntOrNull() ?: 0,
                username = editProxyUser.text.toString().trim(),
                password = editProxyPass.text.toString()
            )
            WalletConfigStore.save(this, SweeperConfig(apiUrls, apiKey, secret, dest, pollMs, feeReserve, proxy))
            tryShowDerivedAddress(secret, txtDerived)
            txtStatus.text = "config saved"
        }

        btnStart.setOnClickListener {
            if (WalletConfigStore.load(this) == null) {
                txtStatus.text = "save a valid config first"
                return@setOnClickListener
            }
            ContextCompat.startForegroundService(this, Intent(this, SweeperService::class.java))
            refreshStatus()
        }

        btnStop.setOnClickListener {
            startService(Intent(this, SweeperService::class.java).setAction(SweeperService.ACTION_STOP))
            refreshStatus()
        }
    }

    override fun onResume() {
        super.onResume()
        SweepLog.setListener { lines -> runOnUiThread { findViewById<TextView>(R.id.txt_log).text = lines.joinToString("\n") } }
        findViewById<TextView>(R.id.txt_status).text = if (SweeperService.isRunning.get()) "status: RUNNING" else "status: stopped"
    }

    override fun onPause() {
        super.onPause()
        SweepLog.setListener(null)
    }

    private fun tryShowDerivedAddress(secret: String, target: TextView) {
        if (secret.isBlank()) { target.text = ""; return }
        try {
            val kp = TronKeypair.parse(secret)
            target.text = "source address: ${kp.address}"
        } catch (e: Exception) {
            target.text = "invalid secret key: ${e.message}"
        }
    }
}
