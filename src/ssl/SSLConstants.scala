package ssl

object SSLConstants {
	// cipher suite
	def SSL_RSA_WITH_RC4_128_MD5 = 0x04

	// compression method
	def NULL_COMPRESS = 0x00

	// version
	def MAJVER: Byte = 0x03
	def MINVER: Byte = 0x00

	// direction
	def CLIENT_TO_SERVER = 0
	def SERVER_TO_CLIENT = 1

	// entity id
	def CLIENT = 0
	def SERVER = 1
}
