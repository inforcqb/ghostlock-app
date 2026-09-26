package com.ghostlock.app.adb

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal adb client: just enough to reach the *device's own* adbd over loopback and run
 * shell commands in it.
 *
 * Why the app has to speak adb at all: after the Magica channel opens the adbd gate
 * (`runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555` + `runcon u:r:usbd:s0 setprop
 * ctl.restart adbd`) the only context on this handset that has full capabilities is the
 * **root adbd shell** (`uid=0`, `u:r:su:s0`, `CapEff=0x1ffffffffff`). The Magica channel
 * itself is uid 0 but `CapBnd=0`, so it can never `rmmod`/`finit_module`.
 *
 * Authorization: the chain opens the gate on purpose ("门禁在利用期间开放"), i.e.
 * `ro.adb.secure=0` is in effect when this client connects, so adbd accepts the
 * connection without an RSA signature. If the device still asks for AUTH, the gate is
 * closed -- that is a chain failure, reported plainly instead of silently retrying.
 *
 * Protocol reference: packet header is 6 little-endian u32 (command, arg0, arg1,
 * data_length, data_crc32, magic=command xor 0xffffffff), header CRC is not verified on
 * this side.
 */
class AdbClient(
    private val host: String = "127.0.0.1",
    private val port: Int = 5555,
) {
    private var socket: Socket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null

    fun connect(connectTimeoutMs: Int = 5_000, readTimeoutMs: Int = 30_000) {
        close()
        val s = Socket()
        s.tcpNoDelay = true
        s.connect(InetSocketAddress(host, port), connectTimeoutMs)
        s.soTimeout = readTimeoutMs
        socket = s
        input = s.getInputStream()
        output = s.getOutputStream()
        send(A_CNXN, A_VERSION, MAX_DATA, "host::features=shell_v2,cmd\u0000".toByteArray())
        // adbd answers CNXN when the gate is open; AUTH means it still wants a signature.
        val deadline = System.currentTimeMillis() + connectTimeoutMs
        while (true) {
            val packet = readPacket()
            when (packet.command) {
                A_CNXN -> return
                A_AUTH -> {
                    val kind = packet.arg0
                    close()
                    throw IllegalStateException(
                        "adbd asked for AUTH (type=$kind): ro.adb.secure is still 1, " +
                            "the gate was not opened",
                    )
                }
                else -> {
                    if (System.currentTimeMillis() > deadline) {
                        close()
                        throw IllegalStateException(
                            "unexpected adb packet 0x${packet.command.toString(16)} while connecting",
                        )
                    }
                }
            }
        }
    }

    /** Run one shell command in the connected adbd and return its combined output. */
    fun exec(command: String, timeoutMs: Int = 60_000): String {
        val out = output ?: throw IllegalStateException("adb client is not connected")
        val sock = socket ?: throw IllegalStateException("adb client is not connected")
        sock.soTimeout = timeoutMs
        val localId = nextLocalId()
        send(A_OPEN, localId, 0, "shell:$command\u0000".toByteArray())
        val builder = StringBuilder()
        while (true) {
            val packet = readPacket()
            when (packet.command) {
                A_WRTE -> {
                    builder.append(String(packet.payload, Charsets.UTF_8))
                    // ack so adbd keeps streaming
                    send(A_OKAY, localId, packet.arg0, ByteArray(0))
                }
                A_CLSE -> return builder.toString().trimEnd('\u0000', '\n', '\r')
                A_OKAY -> Unit
                else -> out.flush()
            }
        }
    }

    fun close() {
        runCatching { socket?.close() }
        socket = null
        input = null
        output = null
    }

    private var localIdCounter = 0
    private fun nextLocalId(): Int = ++localIdCounter

    private fun send(command: Int, arg0: Int, arg1: Int, payload: ByteArray) {
        val out = output ?: throw IllegalStateException("adb client is not connected")
        val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(command)
        header.putInt(arg0)
        header.putInt(arg1)
        header.putInt(payload.size)
        header.putInt(if (payload.isEmpty()) 0 else crc32(payload))
        header.putInt(command xor -0x1)
        out.write(header.array())
        if (payload.isNotEmpty()) out.write(payload)
        out.flush()
    }

    private class Packet(val command: Int, val arg0: Int, val arg1: Int, val payload: ByteArray)

    private fun readPacket(): Packet {
        val ins = input ?: throw IllegalStateException("adb client is not connected")
        val header = readFully(ins, 24)
        val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val command = buf.int
        val arg0 = buf.int
        val arg1 = buf.int
        val length = buf.int
        buf.int // data crc32 (not verified)
        buf.int // magic
        if (length < 0 || length > MAX_DATA) {
            throw IllegalStateException("adb packet length out of range: $length")
        }
        val payload = if (length > 0) readFully(ins, length) else ByteArray(0)
        return Packet(command, arg0, arg1, payload)
    }

    private fun readFully(ins: InputStream, count: Int): ByteArray {
        val data = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = ins.read(data, offset, count - offset)
            if (read <= 0) throw EOFException("adb connection closed after $offset/$count bytes")
            offset += read
        }
        return data
    }

    private fun crc32(data: ByteArray): Int {
        var crc = -0x1
        for (byte in data) {
            crc = crc xor (byte.toInt() and 0xff)
            for (i in 0 until 8) {
                crc = if (crc and 1 != 0) (crc ushr 1) xor 0xEDB88320.toInt() else crc ushr 1
            }
        }
        return crc.inv()
    }

    private companion object {
        const val A_CNXN = 0x4e584e43
        const val A_AUTH = 0x48545541
        const val A_OPEN = 0x4e45504f
        const val A_OKAY = 0x59414b4f
        const val A_CLSE = 0x45534c43
        const val A_WRTE = 0x45545257

        const val A_VERSION = 0x01000001
        const val MAX_DATA = 256 * 1024
    }
}
