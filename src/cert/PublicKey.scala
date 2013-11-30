package cert

import der._

class PublicKey {
	/*
   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
   */

	/*
   AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }
   */

	/*
      RSAPublicKey ::= SEQUENCE {
         modulus            INTEGER, -- n
         publicExponent     INTEGER  -- e -- }
   */

	val rsaEncryption = "1.2.840.113549.1.1.1"
	var modulus: BigInt = null
	var publicExponent: BigInt = null

	def parseAlgorithm(node: DerNode) {
		val seqNode = node.asInstanceOf[SequenceNode]
		val ident = seqNode.getChild(0).asInstanceOf[ObjectIdentifierNode]

		// Note: only handle rsaEncryption right now
		assert(ident.equals(rsaEncryption))
	}

	def parseRSAPublicKey(node: DerNode) {	
		assert(node.isInstanceOf[SequenceNode])
		val topSeq = node.asInstanceOf[SequenceNode]
		assert(topSeq.length == 2)

		modulus = topSeq.getChild(0).asInstanceOf[IntegerNode].value
		publicExponent = topSeq.getChild(1).asInstanceOf[IntegerNode].value
	}

	def parseDerNode(node: DerNode) {	
		val topSeq = node.asInstanceOf[SequenceNode]
		val algoNode = topSeq.getChild(0)
		val rawKey = topSeq.getChild(1)

		parseAlgorithm(algoNode)
		assert(rawKey.isInstanceOf[BitStringNode])
		parseRSAPublicKey(DerNode.decode(rawKey.asInstanceOf[BitStringNode].data))
	}
}
