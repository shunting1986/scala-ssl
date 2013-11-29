package util

import util.Util._

object Base64 {
	// 64 characters
	// A-Z (26)
	// a-z (26)
	// 0-9 (10)
	// +/
	// padding by =

	def charToIndex(ch: Char): Int = {
		if (ch >= 'A' && ch <= 'Z') {
			ch - 'A' + 0 // 0 - 25
		} else if (ch >= 'a' && ch <= 'z') {
			ch - 'a' + 26 // 26 - 51
		} else if (ch >= '0' && ch <= '9') {
			ch - '0' + 52 // 52 to 61
		} else if (ch == '+') {
			62
		} else if (ch == '/') {
			63
		} else if (ch == ' ' || ch == '\n') {
		  -1
		} else {
			sys.error("Invalid base64 character" + ch)
		}
	}

	def decode(_cipher: String): Array[Byte] = {
		var cipher = _cipher
		var i = 0
		var ar = Array[Byte]()
		var missnum = 0
		while (cipher.length > 0 && (cipher.charAt(cipher.length - 1) == '=' ||
			cipher.charAt(cipher.length - 1) == ' ' ||
			cipher.charAt(cipher.length - 1) == '\n')) {
			if (cipher.charAt(cipher.length - 1) == '=') 
				missnum += 1
			cipher = cipher.slice(0, cipher.length - 1)
		}
		assert(missnum <= 2)

		var j = 0
		var v = 0L
		while (i < cipher.length) {
			var ch = cipher.charAt(i)
			val ind = charToIndex(ch)

			if (ind != -1) {
				v = (v << 6) + ind
				j += 1

				if (j == 4) {
					// push
					ar = ar :+ ((v >> 16) & 0xff).asInstanceOf[Byte]
					ar = ar :+ ((v >> 8) & 0xff).asInstanceOf[Byte]
					ar = ar :+ ((v) & 0xff).asInstanceOf[Byte]
					j = 0
					v = 0
				}
			}

			i += 1
		}
		assert((j + missnum) % 4 == 0)
		if (j == 3) {
			ar = ar :+ ((v >> 10) & 0xff).asInstanceOf[Byte]
			ar = ar :+ ((v >> 2) & 0xff).asInstanceOf[Byte]
		} else if (j == 2) {
			ar = ar :+ ((v >> 4) & 0xff).asInstanceOf[Byte]
		} else if (j == 0) {
		} else {
			assert(false)
		}
		ar
	}
}
