package ssl

import java.net.Socket
import ssl._
import util.Util._

class SSLServerConnection(sock: Socket) extends SSLConnection(sock) {
	def recvClientHello = {
		val data = recvRecord(SSLRecord.CT_HANDSHAKE)
		recordHandshake(data)
		(new ClientHello(this)).parse(data)
	}

	def sendServerHello = {
		val hkdata = (new ServerHello(this)).serialize
		recordHandshake(hkdata)
		send(SSLRecord.createHandshake(hkdata).serialize)
	}
}
