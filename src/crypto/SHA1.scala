package crypto

import util.Util

object SHA1 {
	def main(args: Array[String]) {
		val sha1 = new SHA1
		var buf = Util.streamToByteArray(System.in)
		val output = sha1.doHash(buf)
		Util.dumpByteArray(output)
	}
}

class SHA1 {
	// big endian
	// assume v is not negative
	def longToByteArray(v: Long): Array[Byte] = {
		def longToByteArray2(v2: Long, len: Int): Array[Byte] = {
			if (len == 0)
				new Array[Byte](0)
			else 	
				longToByteArray2(v2 >> 8, len - 1) :+ (v2 % 256).asInstanceOf[Byte]
		}
		longToByteArray2(v, 8)
	}

	def byteArrayToLong(buf: Array[Byte]): Long = {
		if (buf.length == 1) {
			buf(0).asInstanceOf[Long] & 0xff
		} else {
			(byteArrayToLong(buf.slice(0, buf.length  -1)) << 8) + (buf(buf.length - 1).asInstanceOf[Long] & 0xff)
		}
	}

	def doPadding(orig: Array[Byte]): Array[Byte] = {
		var output = orig :+ 0x80.asInstanceOf[Byte]
		while ((output.length * 8) % 512 != (512 - 64)) {
			output = output :+ 0x00.asInstanceOf[Byte]
		}

		var bitLen = orig.length * 8L
		output ++ longToByteArray(bitLen)
	}

	def trunc(v: Long): Long = v & 0xffffffffL

	def leftRotate(_v: Long, c: Int): Long = {
		var v = _v
		v = trunc(v)
		trunc((v << c) | (v >> (32 - c)))
	}

	def doHash(input: Array[Byte]): Array[Byte] = {
		val afterPadding = doPadding(input)

		var h0 = 0x67452301L
		var h1 = 0xefcdab89L
		var h2 = 0x98badcfeL
		var h3 = 0x10325476L
		var h4 = 0xc3d2e1f0L

		var offset = 0
		var w = new Array[Long](80)
		while (offset < afterPadding.length) {
			var i = 0 
			while (i < 16) {
				w(i) = byteArrayToLong(afterPadding.slice(offset + i * 4, offset + i * 4 + 4))

				// increment indicator variable
				i += 1
			}

			// extend the sixteen 32-bit works into eighty 32-bit words
			i = 16
			while (i < 80) {
				w(i) = leftRotate((w(i - 3) ^ w(i - 8) ^ w(i - 14) ^ w(i - 16)), 1)
				i += 1
			}

			var a = h0
			var b = h1
			var c = h2
			var d = h3
			var e = h4

			var f = 0L
			var k = 0L

			// main loop
			i = 0
			while (i < 80) {
				if (i < 20) {
					f = (b & c) | (trunc(~b) & d)
					k = 0x5a827999L
				} else if (i < 40) {
					f = b ^ c ^ d
					k = 0x6ed9eba1L
				} else if (i < 60) {
					f = (b & c) | (b & d) | (c & d)
					k = 0x8f1bbcdcL
				} else {
					f = b ^ c ^ d
					k = 0xca62c1d6L
				}

				var temp = leftRotate(a, 5) + f + e + k + w(i)
				temp = trunc(temp)
				e = d
				d = c
				c = leftRotate(b, 30)
				b = a
				a = temp

				// increment indicator variable
				i += 1
			}

			h0 += a
			h1 += b
			h2 += c
			h3 += d
			h4 += e

			h0 = trunc(h0)
			h1 = trunc(h1)
			h2 = trunc(h2)
			h3 = trunc(h3)
			h4 = trunc(h4)

			// increment the indicator variable
			offset += 512 / 8
		}

		longToByteArray(h0).slice(4, 8) ++ longToByteArray(h1).slice(4, 8) ++ longToByteArray(h2).slice(4, 8) ++ longToByteArray(h3).slice(4, 8) ++ longToByteArray(h4).slice(4, 8)
	}
}
