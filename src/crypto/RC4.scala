package crypto

import util._

object RC4 {
	def main(args: Array[String]) {
		val fcont = Util.readFile("/tmp/rc4-key")
		// Util.dumpByteArray(Util.hexToBin(fcont.getBytes))
		val rc4 = new RC4(Util.hexToBin(fcont.getBytes))

		val input = Util.hexToBin(Util.fileToByteArray("/tmp/rc4-plain"))
		Util.dumpByteArray(rc4.encrypt(input))
	}
}

class RC4(key: Array[Byte]) {
	val state = new Array[Int](256)
	val dummy = {
		var i = 0
		while (i < 256) {
			state(i) = i
			i += 1
		}
		var j = 0
		i = 0
		while (i < 256) {
			j = (j + state(i) + (key(i % key.length).asInstanceOf[Int] & 0xff)) % 256
			var t = state(i)
			state(i) = state(j)
			state(j) = t
			i += 1
		}
	}

	var ioff = 0
	var joff = 0
	def nextByte(): Byte = {
		ioff = (ioff + 1) % 256
		joff = (joff + state(ioff)) % 256

		var t = state(ioff)
		state(ioff) = state(joff)
		state(joff) = t
		state((state(ioff) + state(joff)) % 256).asInstanceOf[Byte]
	}

	def encrypt(input: Array[Byte]): Array[Byte] = {
		decrypt(input)
	}

	def decrypt(input: Array[Byte]): Array[Byte] = {
		val output = new Array[Byte](input.length)
		var i = 0
		while (i < input.length) {
			output(i) = (input(i).asInstanceOf[Int] ^ nextByte.asInstanceOf[Int]).asInstanceOf[Byte]
			i += 1
		}
		output
	}
}
