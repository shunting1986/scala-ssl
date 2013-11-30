package ssl

import util.Util._

object SSLRecord {
	def MAJVER: Byte = 0x03
	def MINVER: Byte = 0x00

	def CT_CHANGE_CIPHER_SPEC = 0x14
	def createChangeCipherSpec(data: Array[Byte]): SSLRecord = {
		new SSLRecord(CT_CHANGE_CIPHER_SPEC, data)
	}
}

class SSLRecord(contentType: Int, data: Array[Byte]) {
	def serialize(): Array[Byte] = {
		Array[Byte](contentType.asInstanceOf[Byte], SSLRecord.MAJVER, SSLRecord.MINVER) ++ intToByteArray(data.length, 2) ++ data
	}
}
