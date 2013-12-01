package util

import scala.util.Random
import java.io.InputStream
import scala.io._
import java.io._

object Util {
	/* printing '.' every one second in a forever loop */
	def spin() {
		while (true) {
			print(".")
			Thread.sleep(1000)
		}
	}

	/*
	 * Assume big endian
	 */
	def byteArrayToInt(buf: Array[Byte]): Int = {
		var res = 0
		for (b <- buf) {
			res = (res * 256) + (b.intValue & 0xff)
		}
		res
	}
	
	/* convert an integer to a byte array of the specified length */
	def intToByteArray(value: Int, len: Int): Array[Byte] = {
		if (len == 0) {
			Array[Byte]()
		} else {
			intToByteArray(value / 256, len - 1) :+ (value % 256).asInstanceOf[Byte]
		}
	}
	
	/* generate a randome byte array of the specified length */
	def genRandom(len: Int): Array[Byte] = {
		val a = new Array[Byte](len)
		Random.nextBytes(a)
		a
	}

	/* Dump a byte array */
	def dumpByteArray(bin: Array[Byte]) {
		def width = 16
		def dumpLine(subbin: Array[Byte]) {
			if (subbin.length == 0) 
				println("")
			else {
				printf(" %02x", subbin(0))
				dumpLine(subbin.drop(1))
			}
		}
		if (bin.length <= width) {
			dumpLine(bin)
		} else {
			dumpLine(bin.dropRight(bin.length - width)) 
			dumpByteArray(bin.drop(width))
		}
	}

	/* Hex dump to byte array */
	def hexToBin(hex: Array[Byte]): Array[Byte] = {
		var bin = Array[Byte]()

		var i = 0
		var u = -1
		while (i < hex.length) {
			var item = hex(i)
			var v = -1
			if (item >= '0' && item <= '9') {
				v = item - '0'
			} else if (item >= 'a' && item <= 'f') {
				v = item - 'a' + 10
			} else if (item >= 'A' && item <= 'F') {
				v = item - 'A' + 10
			}

			if (v != -1) {
				if (u == -1) {
					u = v
				} else {
					val bt = u * 16 + v
					u = -1
					bin = bin :+ bt.asInstanceOf[Byte]
				}
			}

			i += 1
		}
		assert(u == -1)
		bin
	}

	/* Convert stream to byte array */
	def streamToByteArray(in: InputStream): Array[Byte] = {
		var res = new Array[Byte](0)
		var buf = new Array[Byte](256)

		def readMore() {
			val r = in.read(buf)
			if (r >= 0) {
				res = res ++ buf.slice(0, r)
				readMore
			} 
		}
		readMore
		res
	}

	// big endian
	def byteArrayToBigInt(ar: Array[Byte]): BigInt = {
		var bi = BigInt(0)
		var i = 0
		while (i < ar.length) {
			val bt = ar(i)
			bi = bi * 256 + (bt.asInstanceOf[Int] & 255)
			i += 1
		}
		bi
	}

	// big endian
	def bigIntToByteArray(_bi: BigInt, nbyte: Int): Array[Byte] = {
		var bi = _bi
		var ar = new Array[Byte](nbyte)
		var i = nbyte - 1
		while (i >= 0) {
			val bt = (bi % 256).byteValue
			bi /= 256

			ar(i) = bt

			// update indicator variable
			i -= 1
		}
		ar
	}

	def readFile(path: String): String = {
		Source.fromFile(path).getLines.mkString("\n")
	}

	def fileToByteArray(path: String): Array[Byte] = {
		val is = new FileInputStream(new File(path))
		streamToByteArray(is)
	}

	def genPadding(len: Int, ct: Byte): Array[Byte] = {
		var i = 0 
		val ar = new Array[Byte](len)
		while (i < len) {
			ar(i) = ct
			i += 1
		}
		ar
	}

	def main(args: Array[String]) {
		val input = streamToByteArray(System.in)
		val output = hexToBin(input)
		System.out.write(output)
	}
}
