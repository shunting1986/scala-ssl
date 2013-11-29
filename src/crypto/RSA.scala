package crypto

import util.Util._

object RSA {
	def main(args: Array[String]) {
		// steam to byte array
		val input = streamToByteArray(System.in)

		// byte array to big number
		val bi = byteArrayToBigInt(input)

		// dump big number + 1
		println(bi.toString(16))
	}
}

class RSA {
}
