import java.net.ServerSocket
import util.Util._

import ssl._

object SSLServer {
	def main(args: Array[String]) {
		val listenSock = new ServerSocket(8888)

		printf("Waiting for connect...\n")
		val workSock = listenSock.accept
		val conn = new SSLServerConnection(workSock)

		conn.recvClientHello // one handshake record
		conn.sendServerHello

		spin
	}
}
