package ssl

import util._
import cert._

class CertificateHS(conn: SSLConnection) {
	def decode(data: Array[Byte]) {
		val reader = new ArrayBasedReader(data)
		val totLen = reader.nextInt(3)

		assert(totLen == reader.leftLength)

		while (reader.hasMore) {
			val certLen = reader.nextInt(3)
			val certData = reader.nextBytes(certLen)
			
			if (conn.serverCert == null) {
				conn.serverCert = new X509Certificate
				conn.serverCert.parseDer(certData)
			} else {
				sys.error("Can not handle multipe certificates from server right now")
			}
		}
		assert(conn.serverCert != null)
	}
}
