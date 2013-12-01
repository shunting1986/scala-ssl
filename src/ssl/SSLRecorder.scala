package ssl

import util.Util._
import ssl.SSLConstants._

object SSLRecord {
	def CT_CHANGE_CIPHER_SPEC = 0x14
	def CT_HANDSHAKE = 0x16

	def createChangeCipherSpec(data: Array[Byte]): SSLRecord = {
		new SSLRecord(CT_CHANGE_CIPHER_SPEC, data)
	}

	def createHandshake(data: Array[Byte]): SSLRecord = {
		new SSLRecord(CT_HANDSHAKE, data)
	}
}

class SSLRecord(contentType: Int, data: Array[Byte]) {
	def serialize(): Array[Byte] = {
		Array[Byte](contentType.asInstanceOf[Byte], MAJVER, MINVER) ++ intToByteArray(data.length, 2) ++ data
	}
}
