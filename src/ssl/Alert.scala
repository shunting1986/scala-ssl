package ssl

object Alert {
	def LEVEL_WARNING = 1

	def DESC_CLOSE_NOTIFY = 0
}

class Alert(level: Int, desc: Int) {
	def decodeLevel: String = {
		if (level == 1) 
			"warning"
		else if (level == 2)
			"fatal"
		else {
			printf("unsupported level value %d\n", level)
			assert(false)
			null
		}
	}

	def decodeDesc: String = {
		if (desc == 0) 
			"close_notify"
		else {
			printf("unsupported desc value %d\n", desc)
			assert(false)
			null
		}
	}

	override def toString: String = {
		"Alert " + decodeLevel + " " + decodeDesc
	}
}
