TZ = UTC # same as Github
export TZ
SHELL := /bin/bash
JDK ?= zulu
JAVA8 ?= /Library/Java/JavaVirtualMachines/$(JDK)-8.jdk/Contents/Home
JAVA11 ?= /Library/Java/JavaVirtualMachines/$(JDK)-11.jdk/Contents/Home
JAVA17 ?= /Library/Java/JavaVirtualMachines/$(JDK)-17.jdk/Contents/Home
JAVA21 ?= /Library/Java/JavaVirtualMachines/$(JDK)-21.jdk/Contents/Home

8:
	JAVA_HOME=$(JAVA8) ./mvnw clean verify
21:
	JAVA_HOME=$(JAVA21) ./mvnw clean verify

test:
	./mvnw clean verify

fastinstall:
	./mvnw -Dmaven.test.skip=true install
