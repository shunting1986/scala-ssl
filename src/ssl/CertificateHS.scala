package ssl

import util._
import util.Util._
import cert._

class CertificateHS(conn: SSLConnection) {
	def cliconn = conn.asInstanceOf[SSLClientConnection]
	///////////////
	// Receive Part
	///////////////
	def decode(data: Array[Byte]) {
		val reader = new ArrayBasedReader(data)
		val totLen = reader.nextInt(3)

		assert(totLen == reader.leftLength)

		while (reader.hasMore) {
			val certLen = reader.nextInt(3)
			val certData = reader.nextBytes(certLen)
			
			if (cliconn.serverCert == null) {
				cliconn.serverCert = new X509Certificate
				cliconn.serverCert.parseDer(certData)
			} else {
				sys.error("Can not handle multipe certificates from server right now")
			}
		}
		assert(cliconn.serverCert != null)
	}
	
	////////////
	// Send Part
	////////////
	def serconn = conn.asInstanceOf[SSLServerConnection]
	def serialize: Array[Byte] = {
		val der = serconn.serverCertDer
		val onecert = intToByteArray(der.length, 3) ++ der
		val payload = intToByteArray(onecert.length, 3) ++ onecert
		Handshake.genCertificate(payload)
	}
}
