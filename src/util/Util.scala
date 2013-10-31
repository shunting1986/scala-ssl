package util

import scala.util.Random

object Util {
	/* printing '.' every one second in a forever loop */
	def spin() {
		while (true) {
			print(".")
			Thread.sleep(1000)
		}
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
}
