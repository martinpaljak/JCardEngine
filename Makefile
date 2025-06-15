TZ = UTC # same as Github
export TZ
SHELL := /bin/bash
JDK ?= zulu
JAVA8 ?= /Library/Java/JavaVirtualMachines/$(JDK)-8.jdk/Contents/Home
JAVA11 ?= /Library/Java/JavaVirtualMachines/$(JDK)-11.jdk/Contents/Home
JAVA17 ?= /Library/Java/JavaVirtualMachines/$(JDK)-17.jdk/Contents/Home
JAVA21 ?= /Library/Java/JavaVirtualMachines/$(JDK)-21.jdk/Contents/Home

8:
	JAVA_HOME=$(JAVA8) ./mvnw -Dmaven.test.skip=true -Dmaven.antrun.skip=true package

test:
	./mvnw -Dmaven.antrun.skip=true clean verify

fastinstall:
	./mvnw -Dmaven.test.skip=true -Dmaven.antrun.skip=true install
