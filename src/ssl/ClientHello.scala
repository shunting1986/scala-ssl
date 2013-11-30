package ssl

import util.Util._

class ClientHello(conn: SSLConnection) extends Handshake(conn) {
	def SSL_RSA_WITH_RC4_128_MD5 = 0x04
	def NULL_COMPRESS = 0x00

	def cipherSuiteList: Array[Byte] = {
		val cs = intToByteArray(SSL_RSA_WITH_RC4_128_MD5, 2)
		intToByteArray(cs.length, 2) ++ cs
	}
	
	def compressMethodList: Array[Byte] = {
		val cm = intToByteArray(NULL_COMPRESS, 1)
		intToByteArray(cm.length, 1) ++ cm
	}

	/* CLIENT_HELLO byte ++ 
	 * size (3 bytes) ++ 
	 * vmaj ++ vmin ++ 
	 * random (32 bytes) ++ 
	 * session id (length + content) ++ 
	 * cipher suite list (len_16 && list) 
	 * ++ compress method list (len_8 && list)
	 */
	def genClientHello(): Array[Byte] = {
		val payload = Array[Byte](MAJVER, MINVER) ++ genRandom(32) ++ Array[Byte](0) ++ cipherSuiteList ++ compressMethodList
		Array[Byte](CLIENT_HELLO) ++ intToByteArray(payload.length, 3) ++ payload
	}
}
