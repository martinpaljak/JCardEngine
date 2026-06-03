// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0

module pro.javacard.engine.adapters {
    requires transitive apdu4j.core;
    requires org.slf4j;
    requires com.fasterxml.jackson.databind;

    exports pro.javacard.engine.adapters;
}
