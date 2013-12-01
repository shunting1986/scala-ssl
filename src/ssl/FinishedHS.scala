package ssl

class FinishedHS(conn: SSLConnection, dir: Int) {
	val md5Hash = new Array[Byte](16)
	val sha1Hash = new Array[Byte](20)

	def serialize: Array[Byte] = {
		val payload = md5Hash ++ sha1Hash
		val plainText = Handshake.genFinished(payload)

		val mackey = if (dir == SSLConstants.CLIENT_TO_SERVER) conn.clientMACKey else conn.serverWriteKey
		val rc4 = if (dir == SSLConstants.CLIENT_TO_SERVER) conn.clientWriteRC4 else conn.serverWriteRC4
		val hmac = (new RecordHMAC(conn)).genHMAC(mackey, SSLRecord.CT_HANDSHAKE.asInstanceOf[Byte], plainText)

		val cipherText = rc4.encrypt(plainText ++ hmac)
		cipherText
	}
}
