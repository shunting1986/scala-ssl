package ssl

import util.Util._
import crypto._
import ssl.SSLConstants._

class FinishedHS(conn: SSLConnection, dir: Int) {
	val SENDER_CLIENT = 0x434c4e54
	val SENDER_SERVER = 0x53525652
	
	val md5Hash = {
		val hash = new MD5
		genFinishedHash(hash, 48)
	}

	val sha1Hash = {
		val hash = new SHA1
		genFinishedHash(hash, 40)
	}

	def genFinishedHash(hashAgt: Hash, paddingLen: Int): Array[Byte] = {
		val sender = if (dir == CLIENT_TO_SERVER) SENDER_CLIENT else SENDER_SERVER
		val padding1 = genPadding(paddingLen, 0x36.asInstanceOf[Byte])
		val padding2 = genPadding(paddingLen, 0x5c.asInstanceOf[Byte])

		val inputItr1 = conn.recordedHandshakes ++ intToByteArray(sender, 4) ++ conn.masterSecret ++ padding1
		val hashItr1 = hashAgt.doHash(inputItr1)

		val inputItr2 = conn.masterSecret ++ padding2 ++ hashItr1
		val hashItr2 = hashAgt.doHash(inputItr2)
		hashItr2
	}

	def serialize: Array[Byte] = {
		val payload = md5Hash ++ sha1Hash
		val plainText = Handshake.genFinished(payload)

		conn.recordHandshakeCond(plainText)

		val rc4 = if (dir == SSLConstants.CLIENT_TO_SERVER) conn.clientWriteRC4 else conn.serverWriteRC4
		var hmac = Array[Byte]()
		val hmacAgt = new RecordHMAC(conn)
		if (dir == SSLConstants.CLIENT_TO_SERVER) {
			hmac = hmacAgt.genClientHMAC(SSLRecord.CT_HANDSHAKE.asInstanceOf[Byte], plainText)
		} else {
			hmac = hmacAgt.genServerHMAC(SSLRecord.CT_HANDSHAKE.asInstanceOf[Byte], plainText)
		}

		val cipherText = rc4.encrypt(plainText ++ hmac)

		cipherText
	}

	private def verifyFinishMsg(data: Array[Byte]) {
		val exp = md5Hash ++ sha1Hash
		assert(byteArrayEq(exp, data))
	}

	def verifyServerFinishMsg(data: Array[Byte]) {
		verifyFinishMsg(data)
	}

	def verifyClientFinishMsg(data: Array[Byte]) {
		verifyFinishMsg(data)
	}
}
