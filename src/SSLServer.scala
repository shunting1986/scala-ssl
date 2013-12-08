import java.net.ServerSocket
import util.Util._

import ssl._

object SSLServer {
	def main(args: Array[String]) {
		assert(args.length == 1)
		val listenSock = new ServerSocket(8888)

		printf("Waiting for connect...\n")
		val workSock = listenSock.accept
		val certPath = args(0)
		val conn = new SSLServerConnection(workSock, certPath)

		conn.recvClientHello // one handshake record
		conn.sendServerHello
		conn.sendServerCertificate

		spin
	}
}
