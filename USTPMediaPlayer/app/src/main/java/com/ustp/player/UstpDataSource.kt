package com.ustp.player

import android.net.Uri
import androidx.media3.common.C
import androidx.media3.datasource.BaseDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSpec
import java.io.IOException

class UstpDataSource(private val client: UstpClient) : BaseDataSource(true) {
    private var opened = false
    private var current: ByteArray? = null
    private var off = 0

    override fun open(dataSpec: DataSpec): Long {
        transferInitializing(dataSpec)
        opened = true
        transferStarted(dataSpec)
        return C.LENGTH_UNSET.toLong()
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (!opened) return C.RESULT_END_OF_INPUT
        while (current == null || off >= (current?.size ?: 0)) {
            current = client.outputQueue.take()
            off = 0
        }
        val src = current ?: return C.RESULT_END_OF_INPUT
        val n = minOf(length, src.size - off)
        System.arraycopy(src, off, buffer, offset, n)
        off += n
        bytesTransferred(n)
        return n
    }

    override fun getUri(): Uri? = Uri.parse("ustp://live")

    override fun close() {
        opened = false
        current = null
        off = 0
        transferEnded()
    }
}

class UstpDataSourceFactory(private val client: UstpClient) : DataSource.Factory {
    override fun createDataSource(): DataSource = UstpDataSource(client)
}
