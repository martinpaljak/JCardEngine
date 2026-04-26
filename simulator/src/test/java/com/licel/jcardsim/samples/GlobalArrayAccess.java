// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.samples;

import javacard.framework.Shareable;
import org.globalplatform.GPRegistryEntry;

/**
 * Grants access to the global array.
 */
public interface GlobalArrayAccess extends Shareable {
    Object getGlobalArrayRef(GPRegistryEntry caller);
}
