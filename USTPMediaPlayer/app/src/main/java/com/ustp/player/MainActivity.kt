package com.ustp.player

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.appcompat.app.AppCompatActivity
import androidx.media3.common.MediaItem
import androidx.media3.datasource.DataSpec
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.source.ProgressiveMediaSource
import androidx.media3.extractor.DefaultExtractorsFactory
import androidx.media3.ui.PlayerView

class MainActivity : AppCompatActivity() {
    private var client: UstpClient? = null
    private var player: ExoPlayer? = null
    private var fullscreen = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val etHost = findViewById<EditText>(R.id.etHost)
        val etPlayoutDelay = findViewById<EditText>(R.id.etPlayoutDelay)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)
        val btnStart = findViewById<Button>(R.id.btnStart)
        val btnFullscreen = findViewById<Button>(R.id.btnFullscreen)
        val playerView = findViewById<PlayerView>(R.id.playerView)
        val fullscreenView = findViewById<PlayerView>(R.id.playerFullscreen)
        val controlPanel = findViewById<LinearLayout>(R.id.controlPanel)

        val fixedServerPort = 40001
        val fixedLocalPort = 40000

        btnStart.setOnClickListener {
            val host = etHost.text.toString().trim()
            val delayMs = etPlayoutDelay.text.toString().toLongOrNull() ?: 140L
            if (host.isEmpty()) {
                tvStatus.text = "Please enter server IP or domain."
                return@setOnClickListener
            }

            client?.stop()
            player?.release()
            try {
                val c = UstpClient(host, fixedServerPort, fixedLocalPort, playoutDelayMs = delayMs)
                client = c
                c.start { msg -> runOnUiThread { tvStatus.text = msg } }

                val exo = ExoPlayer.Builder(this).build()
                player = exo
                playerView.player = exo
                fullscreenView.player = exo

                val dsFactory = UstpDataSourceFactory(c)
                val mediaSource = ProgressiveMediaSource.Factory(dsFactory, DefaultExtractorsFactory())
                    .createMediaSource(MediaItem.fromUri("ustp://live"))

                exo.setMediaSource(mediaSource)
                exo.prepare()
                exo.playWhenReady = true
                tvStatus.text = "Playing over USTP..."
            } catch (e: Exception) {
                tvStatus.text = "Connection failed: ${e.message}"
            }
        }

        btnFullscreen.setOnClickListener {
            fullscreen = !fullscreen
            controlPanel.visibility = if (fullscreen) android.view.View.GONE else android.view.View.VISIBLE
            playerView.visibility = if (fullscreen) android.view.View.GONE else android.view.View.VISIBLE
            fullscreenView.visibility = if (fullscreen) android.view.View.VISIBLE else android.view.View.GONE
            applyFullscreen(fullscreen)
            btnFullscreen.text = if (fullscreen) "Exit Fullscreen" else "Fullscreen Player"
        }
    }

    private fun applyFullscreen(enable: Boolean) {
        WindowCompat.setDecorFitsSystemWindows(window, !enable)
        val controller = WindowInsetsControllerCompat(window, window.decorView)
        controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        if (enable) {
            controller.hide(WindowInsetsCompat.Type.systemBars())
        } else {
            controller.show(WindowInsetsCompat.Type.systemBars())
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        client?.stop()
        player?.release()
    }
}
