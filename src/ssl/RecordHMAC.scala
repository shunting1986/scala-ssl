package ssl

import util.Util._
import crypto._
import ssl.SSLConstants._

object RecordHMAC {
	def main(args: Array[String]) {
		val conn = new SSLClientConnection(null)
		val hmacAgt = new RecordHMAC(conn)

		// get key
		val keyStr = """9d 2e 7f 34 71 95 d4 7d ca a6 ff 69 cd 81 54 26 """

		// get content type
		val ct = 0x16.asInstanceOf[Byte]

		// get data
		val dataStr = """|14 00 00 24 2b 3d c8 13 4d ce 04 8e 2d 91 af 28 
		  | 01 60 eb b3 da 66 e3 16 51 03 cd 33 66 af 92 23 
		  | e0 72 b2 b9 b5 21 44 b0""".stripMargin

		val res = hmacAgt.genHMAC(hexToBin(keyStr.getBytes), ct, hexToBin(dataStr.getBytes), 0)
		dumpByteArray(res)
	}
}

class RecordHMAC(conn: SSLConnection) {
	def fmtSeq(seq: Int): Array[Byte] = {
		intToByteArray(seq, 8)
	}

	def genHMAC(entityId: Int, contentType: Int, data: Array[Byte]): Array[Byte] = {	
		if (entityId == CLIENT) {
			genClientHMAC(contentType, data)
		} else {
			genServerHMAC(contentType, data)
		}
	}

	def genClientHMAC(contentType: Int, data: Array[Byte]): Array[Byte] = {
		val hmac = genHMAC(conn.clientMACKey, contentType.asInstanceOf[Byte], data, conn.clientSeq)
		conn.clientSeq += 1
		hmac
	}

	def genServerHMAC(contentType: Int, data: Array[Byte]): Array[Byte] = {
		val hmac = genHMAC(conn.serverMACKey, contentType.asInstanceOf[Byte], data, conn.serverSeq)
		conn.serverSeq += 1
		hmac
	}

	private def genHMAC(key: Array[Byte], contentType: Byte, data: Array[Byte], seq: Int): Array[Byte] = {
		// NOTE: only handle MD5 right now
		val pad_len = 48

		var inputItr1 = key ++ genPadding(pad_len, 0x36.asInstanceOf[Byte]) ++ fmtSeq(seq) ++ Array[Byte](contentType) ++ intToByteArray(data.length, 2) ++ data
		val md5 = new MD5
		var hashItr1 = md5.doHash(inputItr1)

		var inputItr2 = key ++ genPadding(pad_len, 0x5c.asInstanceOf[Byte]) ++ hashItr1
		var hashItr2 = md5.doHash(inputItr2)
		hashItr2
	}
}
