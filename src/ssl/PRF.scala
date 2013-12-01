package ssl

import crypto._
import util.Util._

object PRF {
	def main(args: Array[String]) {
		val pms = """03 00 a8 8d 2c 82 0d 01 ff 97 88 41 0a 63 b0 83 
		          2e d3 14 3b a3 94 62 9b e0 72 47 37 35 31 44 a0 
		          d7 8d 17 bd 3c 45 28 0f 7b e5 a9 a0 af 76 3a fc """
		val clientRand = """ 52 9a c0 60 68 07 0c 1c 4f 16 f1 a6 1d 0b 37 7c 
		          e8 46 73 8e c5 da 4f 44 49 95 ba 6c ab 4f 17 14 """
		val serverRand = """ 52 9a c0 60 56 d6 e2 b8 a3 0c de c8 0f 0f d5 d1 
		          07 93 6a 2b f5 dd 43 b1 f7 3a af 3b 4f 24 e5 44"""
		val ms = new Array[Byte](48)
		val prfAgt = new PRF
		prfAgt.prf(hexToBin(pms.getBytes), hexToBin(clientRand.getBytes), hexToBin(serverRand.getBytes), ms)

		val keyblock = new Array[Byte](64)
		prfAgt.prf(ms, hexToBin(serverRand.getBytes), hexToBin(clientRand.getBytes), keyblock)
		
		dumpByteArray(keyblock)
	}
}

class PRF {
	def prf(secret: Array[Byte], random1: Array[Byte], random2: Array[Byte], output: Array[Byte]) {
		var off = 0
		val md5Agt = new MD5
		val sha1Agt = new SHA1

		while (off < output.length) {
			var padLen = (off / 16) + 1
			var padding = genPadding(padLen, ('A' + (padLen - 1)).asInstanceOf[Byte])
			var sha1Input = padding ++ secret ++ random1 ++ random2
			var sha1Output = sha1Agt.doHash(sha1Input)

			var md5Input = secret ++ sha1Output
			var md5Output = md5Agt.doHash(md5Input)

			md5Output.copyToArray(output, off, 16)
			off += 16 // the length of MD5 hash
		}
	}
}
