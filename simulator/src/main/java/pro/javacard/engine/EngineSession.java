// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine;

import apdu4j.core.BIBO;

// Session towards a shared simulator. Lock is held while the session is open.
// Close semantics (reset or not) are bound at creation time.
public interface EngineSession extends BIBO {
}
