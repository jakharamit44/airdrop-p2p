package com.airdrop.p2p

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

class AirDropService : Service() {

    companion object {
        private const val CHANNEL_STATUS = "airdrop_status"
        private const val CHANNEL_RX = "airdrop_rx"
        private const val NOTIF_ID_STATUS = 1001
        private var rxNotifId = 2000

        @Volatile
        private var instance: AirDropNode? = null
        private var wakeLock: PowerManager.WakeLock? = null

        fun getNode(context: Context): AirDropNode {
            return instance ?: synchronized(this) {
                instance ?: AirDropNode(context.applicationContext).also { instance = it }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_STATUS,
                "AirDrop Receiver Status",
                NotificationManager.IMPORTANCE_LOW
            )
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_RX,
                "Incoming AirDrop Files",
                NotificationManager.IMPORTANCE_HIGH
            )
        )

        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val statusNotif = NotificationCompat.Builder(this, CHANNEL_STATUS)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("AirDrop P2P Active")
            .setContentText("Encrypted BLE L2CAP + 5GHz Wi-Fi Direct P2P")
            .setContentIntent(openAppIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIF_ID_STATUS,
                statusNotif,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIF_ID_STATUS, statusNotif)
        }

        runCatching {
            val pm = getSystemService(PowerManager::class.java)
            wakeLock = pm?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "airdropp2p:transfer_lock")?.apply {
                setReferenceCounted(false)
            }
        }

        val node = getNode(applicationContext)
        node.onTransferProgress = { fileName, pct, doneBytes, totalBytes, speedBps, isSending ->
            if (pct >= 100 || pct < 0) {
                runCatching { if (wakeLock?.isHeld == true) wakeLock?.release() }
                nm.cancel(1999)
            } else {
                runCatching { wakeLock?.acquire(15 * 60 * 1000L) }
                val speedStr = if (speedBps > 0L) " • ${AirDropNode.formatSpeed(speedBps)}" else ""
                val actionTitle = if (isSending) "Sending via AirDrop" else "Receiving via AirDrop"
                val progressNotif = NotificationCompat.Builder(this, CHANNEL_RX)
                    .setSmallIcon(R.mipmap.ic_launcher)
                    .setContentTitle("$actionTitle ($pct%)$speedStr")
                    .setContentText("$fileName (${AirDropNode.formatBytes(doneBytes)} / ${AirDropNode.formatBytes(totalBytes)})")
                    .setProgress(100, pct, false)
                    .setOngoing(true)
                    .setOnlyAlertOnce(true)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .build()
                nm.notify(1999, progressNotif)
            }
        }
        node.onItemReceived = { item ->
            nm.cancel(1999)
            val notifId = 2000 + (rxNotifId++ % 50)
            val targetIntent = if (item.isUrl) {
                Intent(Intent.ACTION_VIEW, Uri.parse(item.pathOrUrl))
            } else {
                Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                }
            }
            val pi = PendingIntent.getActivity(
                this,
                notifId,
                targetIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            val rxNotif = NotificationCompat.Builder(this, CHANNEL_RX)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle("AirDrop Received: ${item.title}")
                .setContentText(item.pathOrUrl)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pi)
                .build()
            nm.notify(notifId, rxNotif)
        }
        node.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        getNode(applicationContext).start()
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Keep foreground service alive when task is dismissed so background transfers and AirDrop discovery persist.
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        runCatching { if (wakeLock?.isHeld == true) wakeLock?.release() }
        wakeLock = null
        instance?.onTransferProgress = null
        instance?.onItemReceived = null
        if (instance?.isTransferInProgress != true) {
            instance?.stop()
        }
        runCatching {
            val nm = getSystemService(NotificationManager::class.java)
            nm.cancelAll()
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
