package ssl

import util.Util._
import ssl.SSLConstants._
import ssl.SSLRecord._

class ServerHandshake(conn: SSLConnection) extends Handshake(conn) {
	def validateHeader(header: Array[Byte]):Int = {
		val ct = header(0)
		val vermaj = header(1)
		val vermin = header(2)
		val len = byteArrayToInt(header.drop(3))	

		assert(ct == CT_HANDSHAKE)
		assert(vermaj == MAJVER)
		assert(vermin == MINVER)

		len
	}

	def recvServerHandshake = {
		val header = conn.recv(5)
		val len = validateHeader(header)
		var data = conn.recv(len)

		conn.recordHandshake(data)
		while (data.length > 0) {
			assert(data.length >= 4)
			val typ = byteArrayToInt(data.dropRight(data.length - 1))
			data = data.drop(1)

			val sublen = byteArrayToInt(data.dropRight(data.length - 3))
			data = data.drop(3)
			assert(sublen <= data.length)

			val subdata = data.dropRight(data.length - sublen)
			data = data.drop(sublen)

			decodeHandshake(typ, subdata)
		}
	}
}
