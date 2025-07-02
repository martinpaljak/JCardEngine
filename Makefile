TZ = UTC # same as Github
export TZ
SHELL := /bin/bash
JDK ?= zulu
JAVA11 ?= /Library/Java/JavaVirtualMachines/$(JDK)-11.jdk/Contents/Home
JAVA17 ?= /Library/Java/JavaVirtualMachines/$(JDK)-17.jdk/Contents/Home
JAVA21 ?= /Library/Java/JavaVirtualMachines/$(JDK)-21.jdk/Contents/Home

11: today
	JAVA_HOME=$(JAVA11) ./mvnw clean install

17:
	JAVA_HOME=$(JAVA17) ./mvnw clean verify

21:
	JAVA_HOME=$(JAVA21) ./mvnw clean verify

test:
	./mvnw clean verify

fast:
	JAVA_HOME=$(JAVA11) ./mvnw -Dmaven.test.skip=true -Dspotbugs.skip=true clean package

fastinstall:
	./mvnw -Dmaven.test.skip=true install

today:
	# for a dirty tree, set the date to today
	test -z "$(shell git status --porcelain)" || ./mvnw versions:set -DnewVersion=$(shell date +%y.%m.%d)-SNAPSHOT -DgenerateBackupPoms=false
