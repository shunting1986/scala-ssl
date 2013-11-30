package der

import util.ArrayBasedReader

class SequenceNode extends DerNode {
	var nodeList = Vector[DerNode]()
	var seqIdList = Vector[Int]()

	def length = nodeList.length
	
	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		val subreader = new ArrayBasedReader(reader.nextBytes(len))
		while (subreader.hasMore) {
			val optid = subreader.peekInt(1)
			if ((optid & 0xe0) == 0xa0) {
				val seqId = subreader.nextInt(2)
				assert(seqId != -1)
				seqIdList = seqIdList :+ seqId
			} else {
				seqIdList = seqIdList :+ -1
			}
			nodeList = nodeList :+ DerNode.decode(subreader)
		}
		this
	} 

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[SEQUENCE]\n")

		var i = 0
		while (i < seqIdList.length) {
			val seqId = seqIdList(i)
			val node = nodeList(i)

			if (seqId != -1) {
				doIndent(ind)
				printf("<SeqId> %04x\n", seqId)
			}
			node.dump(ind + 2)

			i += 1
		}
	}
}
