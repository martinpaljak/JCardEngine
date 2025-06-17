package pro.javacard.jcardsim.core;

import javacard.framework.Applet;

public class InstallSpec {
    final byte[] aid;
    final Class<? extends Applet> klass;
    final byte[] installData;

    private InstallSpec(byte[] aid, Class<? extends Applet> klass, byte[] installData) {
        this.aid = aid;
        this.klass = klass;
        this.installData = installData;
    }

    public static InstallSpec of(byte[] aid, Class<? extends Applet> klass, byte[] installData) {
        return new InstallSpec(aid, klass, installData == null ? new byte[0] : installData);
    }
}
