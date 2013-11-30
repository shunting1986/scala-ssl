package der

import util._
import util.Util._

class OctetStringNode extends DerNode {
	var data = Array[Byte]()

	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader);
		data = reader.nextBytes(len)
		this
	}

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[OCTET STRING]: ")
		dumpByteArray(data)
	}
}
