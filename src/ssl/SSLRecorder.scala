package ssl

import util.Util._
import ssl.SSLConstants._
import ssl._

object SSLRecord {
	def CT_CHANGE_CIPHER_SPEC = 0x14
	def CT_HANDSHAKE = 0x16
	def CT_APPLICATION_DATA = 0x17

	def createChangeCipherSpec(data: Array[Byte]): SSLRecord = {
		new SSLRecord(CT_CHANGE_CIPHER_SPEC, data)
	}

	def createHandshake(data: Array[Byte]): SSLRecord = {
		new SSLRecord(CT_HANDSHAKE, data)
	}

	def createApplicationData(data: Array[Byte]): SSLRecord = {
		new SSLRecord(CT_APPLICATION_DATA, data)
	}

	def validateHeader(header: Array[Byte], expectedCT: Int):Int = {
		val ct = header(0)
		val vermaj = header(1)
		val vermin = header(2)
		val len = byteArrayToInt(header.drop(3))	

		assert(ct == expectedCT.asInstanceOf[Byte])
		assert(vermaj == MAJVER)
		assert(vermin == MINVER)

		len
	}
}

class SSLRecord(contentType: Int, data: Array[Byte]) {
	def serialize(): Array[Byte] = {
		Array[Byte](contentType.asInstanceOf[Byte], MAJVER, MINVER) ++ intToByteArray(data.length, 2) ++ data
	}
}
