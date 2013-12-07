SCALA_BIN_DIR := /home/shunting/work/ubuntu-contents/learn-lang/lang/scala/scala-2.10.2/bin
SCALA := $(SCALA_BIN_DIR)/scala
SCALAC := $(SCALA_BIN_DIR)/scalac

compile:
	find src -name *.scala | xargs $(SCALAC) -d classes

run:
	@$(SCALA) -classpath classes SSLClient

