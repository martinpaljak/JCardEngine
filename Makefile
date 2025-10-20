TZ = UTC # same as Github
export TZ
SHELL := /bin/bash
JDK ?= zulu
JAVA17 ?= /Library/Java/JavaVirtualMachines/$(JDK)-17.jdk/Contents/Home
JAVA21 ?= /Library/Java/JavaVirtualMachines/$(JDK)-21.jdk/Contents/Home
JAVA25 ?= /Library/Java/JavaVirtualMachines/$(JDK)-25.jdk/Contents/Home

17: today
	JAVA_HOME=$(JAVA17) ./mvnw clean install

21:
	JAVA_HOME=$(JAVA21) ./mvnw clean verify

25:
	JAVA_HOME=$(JAVA25) ./mvnw clean verify

test:
	./mvnw clean verify

fast:
	JAVA_HOME=$(JAVA17) ./mvnw -Dmaven.test.skip=true -Dspotbugs.skip=true clean package

fastinstall:
	./mvnw -Dmaven.test.skip=true -Djacoco.skip=true clean install

today:
	# for a dirty tree, set the date to today
	test -z "$(shell git status --porcelain)" || ./mvnw versions:set -DnewVersion=$(shell date +%y.%m.%d)-SNAPSHOT -DgenerateBackupPoms=false
