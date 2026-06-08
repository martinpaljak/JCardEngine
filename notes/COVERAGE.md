# Code coverage with JCardEngine

## Two modes, two runs

A single JaCoCo agent run cannot measure both your applet and your test/support code. Applet
coverage needs the app class loader excluded (see below), which also drops your test and helper
classes. So coverage comes in two mutually-exclusive runs:

| Mode | Measures | How |
|------|----------|-----|
| **Applet coverage** | your applet, as the engine actually ran it | dump + ant report (most of this doc) |
| **Support coverage** | your tests, helpers, non-applet host code | stock `prepare-agent` + `report` goal |

Gate the two behind a property:

```xml
<profiles>
  <profile>
    <id>applet-coverage</id>
    <activation>
      <property>
        <name>applet.coverage</name>
      </property>
    </activation>
    <!-- agent + ant report from below -->
  </profile>
  <profile>
    <id>support-coverage</id>
    <activation>
      <property>
        <name>!applet.coverage</name>
      </property>
    </activation>
    <!-- stock prepare-agent + report goal -->
  </profile>
</profiles>
```

## Applet coverage

> [!IMPORTANT]
> Applet coverage REQUIRES the class dump plus the ant report. The stock Maven `report` goal
> will report 0% for your applet no matter how you configure it.

Both pieces go in the module that runs your tests.

### 1. Agent: dump what actually ran

```xml
<plugin>
  <groupId>org.jacoco</groupId>
  <artifactId>jacoco-maven-plugin</artifactId>
  <version>0.8.14</version>
  <executions>
    <execution>
      <id>agent</id>
      <!-- live before surefire forks -->
      <phase>test-compile</phase>
      <goals>
        <goal>prepare-agent</goal>
      </goals>
      <configuration>
        <!-- the rewritten bytes the report CRC-matches against -->
        <classDumpDir>${project.build.directory}/jacoco-dump</classDumpDir>
        <!-- drop the app loader's untransformed copy -->
        <exclClassLoaders>*AppClassLoader:*PlatformClassLoader</exclClassLoaders>
      </configuration>
    </execution>
  </executions>
</plugin>
```

### 2. Report: org.jacoco.ant, pointed at the dump

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-antrun-plugin</artifactId>
  <version>3.2.0</version>
  <dependencies>
    <dependency>
      <groupId>org.jacoco</groupId>
      <artifactId>org.jacoco.ant</artifactId>
      <version>0.8.14</version>
    </dependency>
  </dependencies>
  <executions>
    <execution>
      <id>applet-coverage-report</id>
      <phase>verify</phase>
      <goals>
        <goal>run</goal>
      </goals>
      <configuration>
        <target>
          <typedef resource="org/jacoco/ant/antlib.xml"/>
          <report>
            <executiondata>
              <fileset dir="${project.build.directory}" includes="jacoco*.exec"/>
            </executiondata>
            <structure name="example applet coverage">
              <group name="applet">
                <classfiles>
                  <fileset dir="${project.build.directory}/jacoco-dump">
                    <include name="com/example/applet/**"/>
                  </fileset>
                </classfiles>
                <sourcefiles>
                  <fileset dir="${basedir}/src/main/java"/>
                </sourcefiles>
              </group>
            </structure>
            <!-- outside target/, so mvn clean keeps the last report -->
            <html destdir="${coverage.dir}/applet"/>
            <xml destfile="${coverage.dir}/applet/jacoco.xml"/>
          </report>
        </target>
      </configuration>
    </execution>
  </executions>
</plugin>
```

Class files come from the dump (rewritten, CRC-matching), sources from where your applet lives. The task runs at `verify`, after surefire has produced `jacoco*.exec` and filled the
dump. Point `coverage.dir` at your repo root so the report survives `mvn clean`:

```xml
<properties>
  <coverage.dir>${project.basedir}/coverage</coverage.dir>           <!-- single module -->
  <!-- report runs in a test submodule:  ${project.basedir}/../coverage -->
</properties>
```

### Both layouts

The setup is the same; only the `<sourcefiles>` directory changes.

**Applet and tests in one module** - applet in `src/main/java`, tests in `src/test/java`:

```xml
<sourcefiles>
  <fileset dir="${basedir}/src/main/java"/>
</sourcefiles>
```

**Applet in a separate module** (the common case) - the agent and the report both live in the
**test** module, not the applet module and not the parent:

```xml
<sourcefiles>
  <fileset dir="${basedir}/../applet/src/main/java"/>
</sourcefiles>
```

`prepare-agent` only sets the `-javaagent` argLine for the forked test JVM, so it has any
effect only where tests run. In a reactor build the sibling applet module resolves to its
freshly built `target/classes` on the test classpath, so its classes get instrumented for
free when a test touches them. A single `jacoco.exec` and a single `jacoco-dump`, both written
in the test module, capture everything. The report then points `classfiles` at that dump and
`sourcefiles` at the sibling applet's sources.

## Support coverage: stock JaCoCo

Coverage of your tests, helpers and any non-applet host code is the normal JaCoCo workflow -
`prepare-agent` + the Maven `report` goal - because those classes are app-loaded, so on-disk
bytes equal executed bytes. Exclude the applet packages (you measure those the other way):

```xml
<plugin>
  <groupId>org.jacoco</groupId>
  <artifactId>jacoco-maven-plugin</artifactId>
  <version>0.8.14</version>
  <executions>
    <execution>
      <id>agent</id>
      <phase>test-compile</phase>
      <goals>
        <goal>prepare-agent</goal>
      </goals>
    </execution>
    <execution>
      <id>report</id>
      <phase>verify</phase>
      <goals>
        <goal>report</goal>
      </goals>
      <configuration>
        <excludes>
          <exclude>com/example/applet/**</exclude>
        </excludes>
      </configuration>
    </execution>
  </executions>
</plugin>
```

This is a separate run from applet coverage - never both at once.

## Run it and verify

```
$ ./mvnw -Dapplet.coverage verify      # applet coverage  -> coverage/applet/index.html
$ ./mvnw verify                        # support coverage -> stock target/site/jacoco/
```

Open `coverage/applet/index.html`. Your applet packages should now show non-zero line
coverage with highlighted source. If the build dies with
`Can't add different class with same name`, the agent is still instrumenting the app-loaded
copy of your applet: check `exclClassLoaders`.

## Implementation details

How JCardEngine measures its own coverage, the deviations from a stock Maven/JaCoCo workflow:

* The agent gets `classDumpDir` + `exclClassLoaders` to drop the app and platform loaders, so
  only the engine's rewritten applet copy is dumped.
* The report uses the `org.jacoco.ant` `<report>` task, not the Maven `report` goal. Only the
  ant task can point `classfiles` at the dump.
* The two modes are mutually exclusive, keyed on the `applet.coverage` property
  (`!applet.coverage` vs `applet.coverage`).
* Reports land in repo-root `coverage/` (outside `target/`), so `mvn clean` keeps the last one
  and each run overwrites it in place.

Canonical config: the `simulator-coverage` and `applet-coverage` profiles in
`simulator/pom.xml`.
