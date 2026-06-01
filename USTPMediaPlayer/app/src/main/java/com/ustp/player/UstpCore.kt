package com.ustp.player

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

private const val MAGIC = "UST1"
private const val TYPE_DATA = 1
private const val TYPE_ACK = 2
private const val TYPE_RETRANSMIT_REQUEST = 3
private const val TYPE_HELLO = 4
private const val TYPE_CLOSE = 5
private const val HEADER_SIZE = 4 + 1 + 1 + 4 + 8 + 2


data class UstpPacket(
    val type: Int,
    val flags: Int,
    val seq: Long,
    val streamPos: Long,
    val payload: ByteArray
)

class UstpClient(
    private val serverIp: String,
    private val serverPort: Int,
    private val localPort: Int,
    private val keepaliveMs: Long = 120,
    private val playoutDelayMs: Long = 140
) {
    private val running = AtomicBoolean(false)
    private val sock = DatagramSocket(localPort)
    private val serverAddr = InetAddress.getByName(serverIp)

    private val receivedSeq = ConcurrentHashMap.newKeySet<Long>()
    private val byPos = ConcurrentHashMap<Long, ByteArray>()
    private val firstSeenAtMs = ConcurrentHashMap<Long, Long>()
    private val nackLastSentMs = ConcurrentHashMap<Long, Long>()
    private var nextPos = 0L
    private val maxSeqSeen = AtomicLong(0L)
    private val maxPosSeen = AtomicLong(0L)
    @Volatile private var lastDataAtMs: Long = 0L

    val outputQueue = LinkedBlockingQueue<ByteArray>(4096)

    fun start(onStatus: (String) -> Unit) {
        if (running.getAndSet(true)) return
        resetState("client start")

        thread(isDaemon = true, name = "ustp-keepalive") {
            while (running.get()) {
                sendPacket(TYPE_HELLO, 0, 0, 0, 48.toUShort().toString().toByteArray())
                Thread.sleep(keepaliveMs)
            }
        }

        thread(isDaemon = true, name = "ustp-nack") {
            while (running.get()) {
                maybeNack()
                Thread.sleep(30)
            }
        }

        thread(isDaemon = true, name = "ustp-recv") {
            val buf = ByteArray(65535)
            while (running.get()) {
                try {
                    val p = DatagramPacket(buf, buf.size)
                    sock.receive(p)
                    if (p.address.hostAddress != serverIp) continue
                    val pkt = parsePacket(p.data.copyOf(p.length)) ?: continue
                    when (pkt.type) {
                        TYPE_DATA -> handleData(pkt)
                        TYPE_CLOSE -> {
                            onStatus("USTP stream closed")
                            stop()
                        }
                    }
                } catch (e: Exception) {
                    if (running.get()) onStatus("recv error: ${e.message}")
                }
            }
        }

        onStatus("USTP started on :$localPort -> $serverIp:$serverPort")
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        try {
            sock.close()
        } catch (_: Exception) {
        }
    }

    private fun handleData(pkt: UstpPacket) {
        val now = System.currentTimeMillis()
        // If stream was silent for a while, treat this as a fresh session.
        if (lastDataAtMs != 0L && now - lastDataAtMs > 1800L) {
            resetState("data timeout/new session")
        }
        lastDataAtMs = now

        // Detect server/session restart: seq and stream position suddenly go backwards.
        val prevMaxSeq = maxSeqSeen.get()
        val prevMaxPos = maxPosSeen.get()
        if ((prevMaxSeq > 256 && pkt.seq + 128 < prevMaxSeq) ||
            (prevMaxPos > (512 * 1024) && pkt.streamPos + (256 * 1024) < prevMaxPos)) {
            resetState("server restart detected")
        }

        maxSeqSeen.updateAndGet { cur -> if (pkt.seq > cur) pkt.seq else cur }
        maxPosSeen.updateAndGet { cur -> if (pkt.streamPos > cur) pkt.streamPos else cur }

        if (receivedSeq.add(pkt.seq)) {
            sendPacket(TYPE_ACK, 0, pkt.seq, 0, ByteArray(0))
        }
        byPos.putIfAbsent(pkt.streamPos, pkt.payload)
        firstSeenAtMs.putIfAbsent(pkt.streamPos, System.currentTimeMillis())

        // Ordered playout with short delay:
        // receives out-of-order immediately (5/6 can arrive now), but only releases
        // to decoder when contiguous and after playout delay to let missing packet arrive.
        while (true) {
            val chunk = byPos[nextPos] ?: break
            val firstSeen = firstSeenAtMs[nextPos] ?: System.currentTimeMillis()
            if (System.currentTimeMillis() - firstSeen < playoutDelayMs) {
                break
            }
            byPos.remove(nextPos)
            firstSeenAtMs.remove(nextPos)
            outputQueue.offer(chunk)
            nextPos += chunk.size.toLong()
        }
    }

    private fun maybeNack() {
        if (receivedSeq.isEmpty()) return
        val now = System.currentTimeMillis()
        if (lastDataAtMs != 0L && now - lastDataAtMs > 1000L) {
            // Do not keep requesting old retransmits when stream has paused/restarted.
            resetState("nack idle cleanup")
            return
        }
        val mn = receivedSeq.minOrNull() ?: return
        val mx = receivedSeq.maxOrNull() ?: return
        if (mx - mn > 8192) {
            // Safety cap to avoid phantom wide-range retransmit storms.
            return
        }
        var sent = 0
        for (s in mn until mx) {
            if (receivedSeq.contains(s)) continue
            val last = nackLastSentMs[s] ?: 0L
            if (now - last < 180L) continue
            nackLastSentMs[s] = now
            sendPacket(TYPE_RETRANSMIT_REQUEST, 0, s, 0, ByteArray(0))
            sent++
            if (sent >= 16) break
        }
    }

    private fun resetState(reason: String) {
        receivedSeq.clear()
        byPos.clear()
        firstSeenAtMs.clear()
        nackLastSentMs.clear()
        maxSeqSeen.set(0L)
        maxPosSeen.set(0L)
        lastDataAtMs = 0L
        nextPos = 0L
        outputQueue.clear()
        println("[USTP-CLIENT] state reset: $reason")
    }

    private fun sendPacket(type: Int, flags: Int, seq: Long, pos: Long, payload: ByteArray) {
        val b = ByteBuffer.allocate(HEADER_SIZE + payload.size).order(ByteOrder.BIG_ENDIAN)
        b.put(MAGIC.toByteArray())
        b.put(type.toByte())
        b.put(flags.toByte())
        b.putInt(seq.toInt())
        b.putLong(pos)
        b.putShort(payload.size.toShort())
        b.put(payload)
        val raw = b.array()
        sock.send(DatagramPacket(raw, raw.size, serverAddr, serverPort))
    }

    private fun parsePacket(raw: ByteArray): UstpPacket? {
        if (raw.size < HEADER_SIZE) return null
        val b = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(4)
        b.get(magic)
        if (String(magic) != MAGIC) return null
        val type = b.get().toInt() and 0xFF
        val flags = b.get().toInt() and 0xFF
        val seq = b.int.toLong() and 0xffffffffL
        val pos = b.long
        val len = b.short.toInt() and 0xFFFF
        if (HEADER_SIZE + len > raw.size) return null
        val payload = ByteArray(len)
        b.get(payload)
        return UstpPacket(type, flags, seq, pos, payload)
    }
}
