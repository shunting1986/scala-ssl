package cert

import scala.io._
import util._
import der._

class X509Certificate {
	val prefix_mark = "-----BEGIN CERTIFICATE-----"
	val postfix_mark = "-----END CERTIFICATE-----"

	/*
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version shall be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version shall be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version shall be v3
        }
   */
	
	var signatureAlgorithm: DerNode = null
	var signatureValue: DerNode = null
	var publicKey: PublicKey = null

	def setFields(node: DerNode) {
		assert(node.isInstanceOf[SequenceNode])
		val topSeq = node.asInstanceOf[SequenceNode]
		assert(topSeq.length == 3)

		val certSeq = topSeq.getChild(0).asInstanceOf[SequenceNode]
		signatureAlgorithm = topSeq.getChild(1)
		signatureValue = topSeq.getChild(2)
	
		assert(certSeq.length >= 7)
		publicKey = new PublicKey; publicKey.parseDerNode(certSeq.getChild(6))
	}

	def parsePemFile(certPath: String) {
		val fcont = Source.fromFile(certPath).getLines.mkString("\n")
		parsePemStr(fcont)
	}

	def parsePemStr(pemstr: String) {
		val ind_prefix = pemstr.indexOf(prefix_mark)
		val ind_postfix = pemstr.indexOf(postfix_mark)

		assert(ind_prefix >= 0)
		assert(ind_postfix >= 0)
		val body = pemstr.substring(ind_prefix + prefix_mark.length, ind_postfix)
		val der = Base64.decode(body)

		parseDer(der)
	}

	def parseDer(binary: Array[Byte]) {
		val node = DerNode.decode(binary)
		setFields(node)
	}
}
