// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;

import java.util.Set;

public class TestDependencyAnalyzer {

    @Test
    public void testDeps() throws Exception {
        var r = DependencyAnalyzer.getAllPackages(GlobalPlatformTestApplet.class);
        Assertions.assertEquals(Set.of("javacard.framework", "org.globalplatform", "pro.javacard.engine.testapplets.testlib"), r);
    }
}
