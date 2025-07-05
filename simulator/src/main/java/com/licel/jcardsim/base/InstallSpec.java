/*
 * Copyright 2025 Martin Paljak
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.base;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;

public class InstallSpec {
    final byte[] aid;
    final Class<? extends Applet> klass;
    final byte[] installData;

    private InstallSpec(byte[] aid, Class<? extends Applet> klass, byte[] installData) {
        this.aid = aid;
        this.klass = klass;
        this.installData = (installData == null ? new byte[0] : installData.clone());
    }

    public static InstallSpec of(byte[] aid, Class<? extends Applet> klass, byte[] installData) {
        return new InstallSpec(aid, klass, installData);
    }

    public AID getAID() {
        return AIDUtil.create(aid);
    }

    public Class<? extends Applet> getAppletClass() {
        return klass;
    }

    public byte[] getParamters() {
        return installData.clone();
    }
}
