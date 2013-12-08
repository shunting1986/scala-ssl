package ssl

import java.net.Socket
import ssl._
import util.Util._
import cert._

class SSLServerConnection(sock: Socket, certPath: String) extends SSLConnection(sock) {
	val serverCertDer = {
		val certObj = new X509Certificate
		certObj.pemFileToDer(certPath)
	}

	def recvClientHello {
		val data = recvRecord(SSLRecord.CT_HANDSHAKE)
		recordHandshake(data)
		(new ClientHello(this)).parse(data)
	}

	def sendServerHello {
		val hkdata = (new ServerHello(this)).serialize
		recordHandshake(hkdata)
		send(SSLRecord.createHandshake(hkdata).serialize)
	}

	def sendServerCertificate {
		val hkdata = (new CertificateHS(this)).serialize
		recordHandshake(hkdata)
		send(SSLRecord.createHandshake(hkdata).serialize)
	}
}
