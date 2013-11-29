package der

import util.ArrayBasedReader

class IntegerNode extends DerNode {
	var value: BigInt = null
	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		value = reader.nextBigInt(len)
		this
	}
	
	override def dump(ind: Int) {
		doIndent(ind)
		printf("[Integer] %s\n", value.toString(16))
	}
}
