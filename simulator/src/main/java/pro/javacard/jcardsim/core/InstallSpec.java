package pro.javacard.jcardsim.core;

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
