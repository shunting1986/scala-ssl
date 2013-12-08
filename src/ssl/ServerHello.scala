package ssl

import util.Util._
import ssl.SSLConstants._
import util._

class ServerHello(conn: SSLClientConnection) {
	def decode(data: Array[Byte]) {
		val reader = new ArrayBasedReader(data)
		val maj = reader.nextInt(1)
		val min = reader.nextInt(1)
		assert(maj == MAJVER)
		assert(min == MINVER)

		val serverRandom = reader.nextBytes(32)
		conn.serverRandom = serverRandom
		println("Server Random:")
		dumpByteArray(serverRandom)

		val sessionIDLen = reader.nextInt(1)
		val sessionID = reader.nextBytes(sessionIDLen)
		println("Session ID:")
		dumpByteArray(sessionID)

		val cipherSuite = reader.nextInt(2)
		printf("CipherSuite %d\n", cipherSuite)

		val compressMethod = reader.nextInt(1)
		printf("CompressMethod %d\n", compressMethod)

		// assert(!reader.hasMore)
		if (reader.hasMore) {
			printf("+++++++ Server Hello has more information: \n")
			dumpByteArray(reader.getData)
		}
	}
}
