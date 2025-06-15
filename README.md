# `jcardsim` &middot; REBORN


[![Latest release](https://img.shields.io/github/release/martinpaljak/jcardsim.svg)](https://github.com/martinpaljak/jcardsim/releases/latest)
&nbsp;[![Maven version](https://img.shields.io/maven-metadata/v?label=maven&metadataUrl=https%3A%2F%2Fmvn.javacard.pro%2Fmaven%2Fcom%2Fgithub%2Fmartinpaljak%2Fjcardsim%2Fmaven-metadata.xml)](https://gist.github.com/martinpaljak/c77d11d671260e24eef6c39123345cae)
&nbsp;[![MIT licensed](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/martinpaljak/jcardsim/blob/master/LICENSE)
&nbsp;[![Build status](https://github.com/martinpaljak/jcardsim/actions/workflows/robot.yml/badge.svg?branch=next)](https://github.com/martinpaljak/jcardsim/actions)
&nbsp;[![Made in Estonia](https://img.shields.io/badge/Made_in-Estonia-0072CE)](https://estonia.ee)

> [!IMPORTANT]
> **TL;DR**: this is a **fork** of the original upstream [@licel/jcardsim](https://github.com/licel/jcardsim) from April 3, 2024 revision `aa60a02f042c18211e4d0f0aef75f27b0e5cf873`.
>
> Longer rationale: Oracle's simulator has gone a long way during 2024/2025 from the `cref` era to the current, regularly released and quite pleasant and functional variant (PC/SC adapter for Linux, Global Platform support etc) as it exists at 25.0 release.
>
> This fork intends to be an up to date alternative to the original jcardsim (by being maintained) and Oracle's simulator (by playing on the strong cards of open source and pure java), with the main purpose of getting test coverage info for applet codebases. Something that's a bit more difficult with the closed source, black box Oracle simulator. Some extra effort will be made to support easy mocking of proprietary packages/interfaces.
>
> Versioning shall use CalVer (YY.MM.DD), with no claims relating to JavaCard specification versions or SDK releases, but initial claim shall continue to be "somewhere close to 3.0.5". PR-s fixing missing API features are most welcome!
>
> Github shall publish automatic releases to [`mvn.javacard.pro`](https://gist.github.com/martinpaljak/c77d11d671260e24eef6c39123345cae) (the same as for [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) and [ant-javacard](https://github.com/martinpaljak/ant-javacard)) and the intended use shall be via Maven dependency (no shaded-for-android JAR-s etc). Some features that are not relevant or available on real life JavaCard-s shall probably be pruned.

More information on how to build and use is available in the [Wiki](https://github.com/martinpaljak/jcardsim/wiki).


----

jCardSim is an open source simulator for Java Card, v3.0.5:

* `javacard.framework.*`
* `javacard.framework.security.*`
* `javacardx.crypto.*`

Key Features:

* Rapid application prototyping
* Simplifies unit testing (5 lines of code)

```java
// 1. create simulator
CardSimulator simulator = new CardSimulator();

// 2. install applet
AID appletAID = AIDUtil.create("F000000001");
simulator.installApplet(appletAID, HelloWorldApplet.class);

// 3. select applet
simulator.selectApplet(appletAID);

// 4. send APDU
CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
ResponseAPDU response = simulator.transmitCommand(commandAPDU);

// 5. check response
assertEquals(0x9000, response.getSW());
```

* easy interaction with `javax.smartcardio` or use from existing PC/SC applications with adapters like `vsmartcard` or Oracle's JavaCard simulator PC/SC driver.

<sub>Oracle and Java are trademarks of Oracle Corporation.</sub>
