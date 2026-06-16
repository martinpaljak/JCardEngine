// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.testng.annotations.Test;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;

import java.util.Set;

import static org.testng.Assert.*;

public class TestDependencyAnalyzer {

    @Test
    public void testDeps() throws Exception {
        var r = DependencyAnalyzer.getAllPackages(GlobalPlatformTestApplet.class);
        assertEquals(r, Set.of("javacard.framework", "org.globalplatform", "pro.javacard.engine.testapplets.testlib", "java.lang"));
    }
}
