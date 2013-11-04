package der

import util.ArrayBasedReader
import util.Util._

class DerDecoder {
	def decodeLength(reader: ArrayBasedReader): Int = {
		var first = reader.nextInt(1)
		if ((first & 0x80) != 0) {
			first = first & ~0x80
			reader.nextInt(first)
		} else {
			first	
		}
	}

	// NOTE: the same as sequence?
	def decodeSet(reader: ArrayBasedReader) {
		printf("[SET]\n")
		val len = decodeLength(reader)

		val subreader = new ArrayBasedReader(reader.nextBytes(len))
		while (subreader.hasMore) {
			decode(subreader)
		}
	}

	def decodeSequence(reader: ArrayBasedReader) {
		printf("[SEQUENCE]\n")
		val len = decodeLength(reader)
		
		val subreader = new ArrayBasedReader(reader.nextBytes(len))
		while (subreader.hasMore) {
			val optid = subreader.peekInt(1)
			if ((optid & 0xe0) == 0xa0) {
				printf("[SEQID %04x]\n", subreader.nextInt(2))
			}
			decode(subreader)
		}
	}

	def decodeInteger(reader: ArrayBasedReader) {
		val len = decodeLength(reader)
		printf("[Integer] %d\n", reader.nextInt(len))
	}

	def decodeNull(reader: ArrayBasedReader) {
		val len = decodeLength(reader)
		assert(len == 0)
		printf("[NULL]\n")
	}

	def decodePrintableString(reader: ArrayBasedReader) {
		val len = decodeLength(reader)
		val data = reader.nextBytes(len)
		printf("[PrintableString]: %s\n", new String(data))
	}

	def decodeUTCTime(reader: ArrayBasedReader) {
		val len = decodeLength(reader)
		val data = reader.nextBytes(len);
		printf("[UTCTime]: %s\n", new String(data))
	}

	def decodeBitString(reader: ArrayBasedReader) {
		val len = decodeLength(reader);
		assert(len > 0)
		val unused = reader.nextInt(1)
		val data = reader.nextBytes(len - 1)
		printf("[BitString] unused %d, data:\n", unused)
		dumpByteArray(data)
	}

	def decodeOctetString(reader: ArrayBasedReader) {
		val len = decodeLength(reader);
		val data = reader.nextBytes(len)
		printf("[OCTET STRING]: ")
		dumpByteArray(data)
	}

	def decodeObjectIdentifier(reader: ArrayBasedReader) {
		val len = decodeLength(reader)
		val data = reader.nextBytes(len)

		val subreader = new ArrayBasedReader(data)
		val first = subreader.nextInt(1)
		printf("[Object Identifier]: ")
		printf("%d.%d", first / 40, first % 40)
		while (subreader.hasMore) {
			var v = 0
			var b = 0
			var brk = false
			while (subreader.hasMore && !brk) {
				b = subreader.nextInt(1)
				v = v * 128 + (b & ~0x80)
				if ((b & 0x80) == 0) {
					brk = true // scala does not have break statement
				}
			}
			assert((b & 0x80) == 0)
			printf(".%d", v)
		}
		printf("\n")
	}

	def decode(bin: Array[Byte]) {
		val reader = new ArrayBasedReader(bin)
		decode(reader)
		assert(!reader.hasMore)
	}

	def decode(reader: ArrayBasedReader) {
		val typeByte = reader.nextInt(1)

		if (typeByte == 0x30) { // sequence 
			decodeSequence(reader)
		} else if (typeByte == 0x31) { // set
			decodeSet(reader)
		} else if (typeByte == 0x02) { // integer
			decodeInteger(reader)
		} else if (typeByte == 0x06) { // object identifier
			decodeObjectIdentifier(reader)
		} else if (typeByte == 0x05) { // null
			decodeNull(reader)
		} else if (typeByte == 0x13) { // printable string
			decodePrintableString(reader)
		} else if (typeByte == 0x17) { // UTCTime
			decodeUTCTime(reader)
		} else if (typeByte == 0x03) { // BIT String
			decodeBitString(reader)
		} else if (typeByte == 0x04) { // OCTET String
			decodeOctetString(reader)
		} else {
			printf("type is 0x%02x\n", typeByte)
			sys.error("unsupported ASN.1 type")
		}
	}
}
