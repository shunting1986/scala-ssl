import java.net.ServerSocket
import util.Util._

import ssl._
import http._

object SSLServer {
	def main(args: Array[String]) {
		assert(args.length == 2)
		val listenSock = new ServerSocket(8888)

		printf("Waiting for connect...\n")
		val workSock = listenSock.accept
		val certPath = args(0)
		val keyPath = args(1)
		val conn = new SSLServerConnection(workSock, certPath, keyPath)

		conn.recvClientHello // one handshake record
		conn.sendServerHello
		conn.sendServerCertificate
		conn.sendServerHelloDone

		conn.recvClientKeyExchange
		conn.recvClientChangeCipherSpec
		conn.recvClientFinishedHandshake

		conn.sendServerChangeCipherSpec
		conn.sendServerFinishedHandshake

		var requestStr = ""
		while (requestStr.indexOf("\n\n") == -1 && requestStr.indexOf("\r\n\r\n") == -1) {
			val data =conn.recvAppData
			requestStr += new String(data)
		}
		printf("============ BEGIN Request ===========\n")
		printf(requestStr)
		printf("============ END   Request ===========\n")

		val httpReq = new HTTPRequest(requestStr)
		val respStr = "You want to " + httpReq.method + " " + httpReq.uri + "\n"
		printf(respStr)

		/*
		val httpResp = new HTTResponse("You want to " + httpReq.method + " " + httpReq.uri + "\n")
		conn.sendAppData(httpResp.getBytes)
		 */
		
		spin
	}
}
