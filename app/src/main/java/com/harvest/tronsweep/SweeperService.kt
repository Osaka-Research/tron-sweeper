package com.harvest.tronsweep

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicBoolean

class SweeperService : Service() {

    companion object {
        const val CHANNEL_ID = "tron_sweeper_channel"
        const val NOTIF_ID = 1
        val isRunning = AtomicBoolean(false)
        const val ACTION_STOP = "com.harvest.tronsweep.ACTION_STOP"
    }

    private val scope = CoroutineScope(Dispatchers.IO + Job())
    private val sweepLock = Mutex()
    private var cooldownUntilMs = 0L

    private var config: SweeperConfig? = null
    private var keypair: TronKeypair? = null

    override fun onBind(intent: Intent?) = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelfSweeper()
            return START_NOT_STICKY
        }

        val cfg = WalletConfigStore.load(this)
        if (cfg == null) {
            SweepLog.add("cannot start: no saved config")
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            keypair = TronKeypair.parse(cfg.sourceSecretKey)
            Base58.decodeCheck(cfg.destAddress) // validates it's a real Tron address
        } catch (e: Exception) {
            SweepLog.add("cannot start: ${e.message}")
            stopSelf()
            return START_NOT_STICKY
        }
        config = cfg

        startForeground(NOTIF_ID, buildNotification("watching …"))
        isRunning.set(true)
        SweepLog.add("service started · source=${keypair!!.address} · dest=${cfg.destAddress} · ${cfg.apiUrls.size} api(s)")

        scope.launch { pollLoop() }

        return START_STICKY
    }

    private fun stopSelfSweeper() {
        isRunning.set(false)
        SweepLog.add("service stopped")
        scope.coroutineContext[Job]?.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        isRunning.set(false)
        scope.coroutineContext[Job]?.cancel()
        super.onDestroy()
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Tron Sweeper", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val stopIntent = Intent(this, SweeperService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Tron Sweeper active")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .addAction(0, "Stop", stopPending)
            .build()
    }

    private suspend fun pollLoop() {
        val cfg = config ?: return
        while (isRunning.get()) {
            val results = cfg.apiUrls.map { api ->
                scope.async {
                    try {
                        val sun = withTimeoutOrNull(4000) {
                            TronApiClient.getBalanceSun(api, keypair!!.address, cfg.apiKey, cfg.proxy)
                        }
                        if (sun != null) api to sun else null
                    } catch (_: Exception) {
                        null
                    }
                }
            }
            for (deferred in results) {
                val result = try { deferred.await() } catch (_: Exception) { null }
                if (result != null) {
                    val (api, sun) = result
                    maybeSweep(sun, api)
                }
            }
            delay(cfg.pollIntervalMs.toLong())
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(clean[i * 2], 16) shl 4) + Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
        return out
    }

    private suspend fun maybeSweep(balanceSun: Long, seenFromApi: String) {
        val cfg = config ?: return
        val reserve = cfg.feeReserveSun
        if (balanceSun <= reserve) return
        if (System.currentTimeMillis() < cooldownUntilMs) return

        sweepLock.withLock {
            if (System.currentTimeMillis() < cooldownUntilMs) return@withLock
            val amount = balanceSun - reserve
            SweepLog.add("balance $balanceSun sun seen via $seenFromApi → sweeping $amount sun")

            val created = try {
                TronApiClient.createTransferTransaction(seenFromApi, keypair!!.address, cfg.destAddress, amount, cfg.apiKey, cfg.proxy)
            } catch (e: Exception) {
                SweepLog.add("sweep failed: could not create tx: ${e.message}")
                return@withLock
            }

            val signatureHex = try {
                keypair!!.signHashToHex(hexToBytes(created.txIdHex))
            } catch (e: Exception) {
                SweepLog.add("sweep failed: could not sign tx: ${e.message}")
                return@withLock
            }

            created.raw.put("signature", JSONArray().put(signatureHex))

            val sendResults = cfg.apiUrls.map { api ->
                scope.async {
                    try {
                        val txid = withTimeoutOrNull(8000) {
                            TronApiClient.broadcastTransaction(api, created.raw, cfg.apiKey, cfg.proxy)
                        }
                        if (txid != null) api to txid else null
                    } catch (e: Exception) {
                        SweepLog.add("broadcast to $api failed: ${e.message}")
                        null
                    }
                }
            }
            val accepted = sendResults.awaitAll().filterNotNull()
            if (accepted.isEmpty()) {
                SweepLog.add("sweep failed: no API accepted the broadcast")
            } else {
                for ((api, txid) in accepted) {
                    SweepLog.add("accepted by $api → txid $txid")
                }
                updateNotificationSwept(amount, accepted.first().second)
            }

            cooldownUntilMs = System.currentTimeMillis() + 3000
        }
    }

    private fun updateNotificationSwept(amountSun: Long, txid: String) {
        val trx = amountSun / 1_000_000.0
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification("swept %.6f TRX · %s".format(trx, txid.take(8))))
    }
}
