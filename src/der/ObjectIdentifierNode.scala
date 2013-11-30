package der

import util.ArrayBasedReader

class ObjectIdentifierNode extends DerNode {
	var idList = Vector[Int]()
	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		val data = reader.nextBytes(len)

		val subreader = new ArrayBasedReader(data)
		val first = subreader.nextInt(1)
		idList = idList :+ (first / 40)
		idList = idList :+ (first % 40)
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
			idList = idList :+ v
		}
		this
	}

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[Object Identifier]: ")
		var first = true
		for (id <- idList) {
			if (!first) {
				printf(".")
			}
			printf("%d", id)
			first = false
		}
		printf("\n")
	}

	def equals(str: String): Boolean = {
		val compList = str.split("\\.")
		if (idList.length != compList.length) {
			false
		} else {
			def equalsComp(i: Int): Boolean = {
				if (i == idList.length) 
					true
				else {
					val expVal = idList(i)
					val actStr = compList(i)
					val actVal = Integer.parseInt(actStr)

					if (expVal != actVal) 
						false
					else 
						equalsComp(i + 1)
				}
			}
			equalsComp(0)
		}
	}
}
