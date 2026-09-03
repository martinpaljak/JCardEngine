# Comment trace

Log the comments of your applet source as the engine runs the code below them.
The applet artifact stays a plain JavaCard class set: the build step adds only data, the engine adds the calls at load time.

## Quickstart

Write comments inside method bodies, in whatever form your project uses to mark a meaningful line:

```java
// step: Dispatch on INS
switch (buffer[ISO7816.OFFSET_INS]) {
```

Add the plugin to the applet module (the one that runs `javac`):

```xml
<plugin>
    <groupId>pro.javacard</groupId>
    <artifactId>jcardengine-maven-plugin</artifactId>
    <version>26.09.02-SNAPSHOT</version>
    <executions>
        <execution>
            <goals>
                <goal>trace</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

The build records every `//` line inside a method body, without a convention of its own. One regex, searched in each recorded line, brings in yours: `step:` for the form above, `REQ_\d+` for `// REQ_123: ...` tags, `.` for every comment. Unset means silent:

* Tests: `Preferences.of(JavaCardEngine.TRACE_FILTER, "step:")` on the `Builder`, or `-Djcardengine.trace.filter=step:`
* jcard.jar: `java -Djcardengine.trace.filter=step: -jar jcard.jar --vsmartcard applet.jar`

```
[INFO] trace - MemoryApplet.java:91 // step: Dispatch on INS
```

## What gets logged, and when

A comment logs when the first line of code below it runs, and it logs every time that line runs. The comment text below says what each one does.

```java
import javacard.framework.ISOException;

// above the class, never logged
public class Flow {
    // above a field, never logged
    static int total;
    static final boolean DEBUG = false;

    static {
        // static initializer, logged once when the class initializes
        total = 0;
    }

    // above a constructor, never logged
    public Flow(int n) {
        // first line of a constructor, logged before super() runs
        super();
        // after super(), logged once per construction
        total = n;
    }

    // above a method, never logged
    public static void run(int n, byte ins) {
        // start of method, logged once per call
        total = 0;
        if (DEBUG) {
            // inside code javac removed: dropped at build time and reported, never logged
            total = -1;
        }
        // above while, logged once when control reaches the loop
        while (n > 0) {
            // inside while, logged per iteration
            n--;
        }
        // above for, logged once
        for (int i = 0; i < 2; i++) {
            // inside for, logged per iteration
            total += i;
        }
        // above if, logged once per pass, whichever branch runs
        if (total > 100) {
            // then branch, logged only when taken
            total = 100;
        } else {
            // else branch, logged only when taken
            total = -total;
            // no code below it in this block: dropped at build time and reported, never logged
        }
        // above try, logged once per pass
        try {
            // inside try, logged once per pass
            if (ins == 2) {
                // about to throw, logged only when thrown
                ISOException.throwIt((short) 0x6A80);
            }
        } catch (ISOException e) {
            // inside catch, logged only when thrown
            total = e.getReason();
        } finally {
            // inside finally, logged on the normal path only: javac copies the finally body per exit path
            total++;
        }
        // above switch, logged once per pass
        switch (ins) {
            case 1:
                // case 1, logged only when this case runs
                total += 10;
                break;
            default:
                // default, logged only when no case matched
                total += 20;
        }
        // end of a void method, logged when it returns
    }
}
```

A comment attaches to the next line of code below it inside its own block. When there is none, the build drops the comment and prints its path and line. That covers a comment written as the last line of a nested block, and a comment inside code javac removed, such as an `if (DEBUG)` block behind a `static final boolean DEBUG = false`. The closing brace of a void method or constructor is a code line, javac puts the implicit return there, so a comment written as its last line logs when the method returns. The same goes for the last line of a `do` body: the `} while (c);` line holds the condition, so the comment logs per iteration. A comment inside `finally` is the known gap: javac emits one copy of the finally body per exit path and only the first copy, the normal one, is instrumented. Put the comment in the `catch` and after the `try` instead.

The call goes in before the first instruction of the line, so a comment above `ISOException.throwIt(...)` is logged and then the exception flies. A JaCoCo probe sits after the line, so it never sees a throwing line complete.

## Format

Each class gets one class-level attribute named `CommentTrace`, next to `SourceFile` and `InnerClasses`. JVMS 4.7 lets a tool define its own attributes and requires every reader to ignore the ones it does not know, so `java`, `javac` and shading pass it through. Bytecode is untouched.

Layout: `u2 count`, then per entry `u2 line`, `u1 once` and `u2 index` of a `CONSTANT_Utf8` holding `File.java:NN // text`. `once` is set for a comment written above a loop. `line` is the code line the comment anchors to: the nearest following entry in the `LineNumberTable` of any class compiled from that source file, so a comment above a nested class method anchors into that nested class. Every class of one source file carries the same map; a class only fires the lines it has. A class without body comments carries an empty one, which marks it as processed.

## How it works

1. **Build**, `trace` goal at `prepare-package`, in place on `target/classes`, idempotent: javac's own parser (`com.sun.source`) gives the line ranges of every block, switch case and loop. Only `//` lines inside a block qualify, a comment above a class, field or method never fires. Line tables are pooled per `SourceFile`, each comment is anchored to the next code line within its block or dropped and reported, and ASM writes the attribute. Sources are read only at build time.
2. **Load**: the engine reloads applet classes through its own class loader. With no filter set the attribute passes through untouched and no call is injected. With a filter, `CommentTraceInterceptor` reads the attribute, drops it, and inserts `Simulator.trace("...")` at the first instruction of each anchored line, once per line per method. So a comment inside a loop body logs per iteration and a comment inside an `if` logs only when the branch is taken. A `once` comment lands before a fresh label and the loop's backward jumps are retargeted to that label, so the call runs when control enters the loop and is skipped on every iteration. A class without the attribute was not built with the trace goal and is reported with a warning when it loads.
3. **Run**: `Simulator.trace` logs the line to `pro.javacard.engine.trace` at INFO when the current card's `jcardengine.trace.filter` finds a match.

Keep the CAP build on its own `javac` run from `src`. The Java-side classes carry the attribute, the converter never needs to see them. The engine and the plugin MUST be the same version.
