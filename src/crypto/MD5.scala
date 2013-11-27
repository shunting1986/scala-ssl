package crypto

/* NOTE: MD5 algorithm can handle any bitstring, but we only handle byte string here */

import util.Util

object MD5 {
	def main(args: Array[String]) {
		val md5 = new MD5
		var buf = Util.streamToByteArray(System.in)
		val output = md5.doHash(buf)
		Util.dumpByteArray(output)
	}
}

class MD5 {
	def k = Array[Long](
		0xd76aa478L, 0xe8c7b756L, 0x242070dbL, 0xc1bdceeeL,
		0xf57c0fafL, 0x4787c62aL, 0xa8304613L, 0xfd469501L,
		0x698098d8L, 0x8b44f7afL, 0xffff5bb1L, 0x895cd7beL,
		0x6b901122L, 0xfd987193L, 0xa679438eL, 0x49b40821L,
		0xf61e2562L, 0xc040b340L, 0x265e5a51L, 0xe9b6c7aaL,
		0xd62f105dL, 0x02441453L, 0xd8a1e681L, 0xe7d3fbc8L,
		0x21e1cde6L, 0xc33707d6L, 0xf4d50d87L, 0x455a14edL,
		0xa9e3e905L, 0xfcefa3f8L, 0x676f02d9L, 0x8d2a4c8aL,
		0xfffa3942L, 0x8771f681L, 0x6d9d6122L, 0xfde5380cL,
		0xa4beea44L, 0x4bdecfa9L, 0xf6bb4b60L, 0xbebfbc70L,
		0x289b7ec6L, 0xeaa127faL, 0xd4ef3085L, 0x04881d05L,
		0xd9d4d039L, 0xe6db99e5L, 0x1fa27cf8L, 0xc4ac5665L,
		0xf4292244L, 0x432aff97L, 0xab9423a7L, 0xfc93a039L,
		0x655b59c3L, 0x8f0ccc92L, 0xffeff47dL, 0x85845dd1L,
		0x6fa87e4fL, 0xfe2ce6e0L, 0xa3014314L, 0x4e0811a1L,
		0xf7537e82L, 0xbd3af235L, 0x2ad7d2bbL, 0xeb86d391L
	)

	def r = Array[Int](
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	)

	// little endian
	// assume v is not negative
	def longToByteArray(_v: Long) : Array[Byte] = {
		var v = _v
		var buf = new Array[Byte](0)
		var i = 0
		while (i < 8) {
			buf = buf :+ (v % 256).asInstanceOf[Byte]
			v = v / 256L
			i += 1
		}
		buf
	}

	def byteArrayToLong(buf: Array[Byte]): Long = {
		assert(buf.length == 4) // only handle 4 bytes right now
		var value = 0L
		var i = buf.length - 1
		while (i >= 0) {
			value = (value << 8) + (buf(i).asInstanceOf[Long] & 0xff)
			i -= 1
		}
		value
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
		var afterPadding = doPadding(input)
		var h0 = 0x67452301L
		var h1 = 0xefcdab89L
		var h2 = 0x98badcfeL
		var h3 = 0x10325476L

		var offset = 0
		var w = new Array[Long](16)
		while (offset < afterPadding.length) {
			var i = 0
			while (i < 16) {
				w(i) = byteArrayToLong(afterPadding.slice(offset + i * 4, offset + i * 4 + 4)) 

				// increment indicator variable
				i += 1
			}

			var a = h0
			var b = h1
			var c = h2
			var d = h3

			var f = 0L
			var g = 0L

			i = 0
			while (i < 64) {
				if (i < 16) {
					f = (b & c) | ((~b) & d)
					g = i
				} else if (i < 32) {
					f = (d & b) | ((~d) & c)
					g = (5 * i + 1) % 16
				} else if (i < 48) {
					f = b ^ c ^ d
					g = (3 * i + 5) % 16
				} else {
					f = c ^ (b | (~d))
					g = (7 * i) % 16
				}

				f = trunc(f)
				g = trunc(g)

				var temp = d
				d = c
				c = b
				b = b + leftRotate(a + f + k(i) + w(g.asInstanceOf[Int]), r(i))
				a = temp

				a = trunc(a)
				b = trunc(b)
				c = trunc(c)
				d = trunc(d)

				// inrement indicator variable
				i += 1
			}

			h0 += a
			h1 += b
			h2 += c
			h3 += d

			h0 = trunc(h0)
			h1 = trunc(h1)
			h2 = trunc(h2)
			h3 = trunc(h3)
			
			// increment indicator variable
			offset += 512 / 8
		}
		longToByteArray(h0).slice(0, 4) ++ longToByteArray(h1).slice(0, 4) ++ longToByteArray(h2).slice(0, 4) ++ longToByteArray(h3).slice(0, 4) 
	}
}
