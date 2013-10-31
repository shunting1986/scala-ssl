package ssl

import util.Util._

class Handshake {
	def HANDSHAKE: Byte = 0x16

	def MAJVER: Byte = 0x03
	def MINVER: Byte = 0x00

	def toHandshake(msg: Array[Byte]) : Array[Byte] = {
		Array[Byte](HANDSHAKE, MAJVER, MINVER) ++ intToByteArray(msg.length, 2) ++ msg
	}
}
