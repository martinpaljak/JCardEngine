package pro.javacard.jcardsim.tool;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

// Use ASM to filter out classes that extend javacard.framework.Applet
// and have static install(byte[], short, byte) method
public class InstallableAppletChecker {

    public static boolean isValidApplet(Path classFilePath, ClassLoader cl) {
        try {
            ClassReader reader = new ClassReader(Files.readAllBytes(classFilePath));
            AppletVisitor visitor = new AppletVisitor(cl);
            reader.accept(visitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            return visitor.isValid();
        } catch (IOException e) {
            throw new RuntimeException("Error reading class file", e);
        }
    }

    private static class AppletVisitor extends ClassVisitor {
        private final ClassLoader cl;
        private String superName;
        private boolean hasInstall;

        AppletVisitor(ClassLoader cl) {
            super(Opcodes.ASM9);
            this.cl = cl;
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.superName = superName;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if ((access & Opcodes.ACC_STATIC) != 0 && "install".equals(name) && "([BSB)V".equals(descriptor)) {
                hasInstall = true;
            }
            return null;
        }

        boolean isValid() {
            return hasInstall && extendsApplet();
        }

        private  static byte[] readAllBytes(InputStream inputStream) throws IOException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        }

        private boolean extendsApplet() {
            String current = superName;
            while (current != null && !"java/lang/Object".equals(current)) {
                if ("javacard/framework/Applet".equals(current)) return true;
                try (InputStream is = cl.getResourceAsStream(current + ".class")) {
                    if (is == null) return false;
                    current = new ClassReader(readAllBytes(is)).getSuperName();
                } catch (IOException e) {
                    return false;
                }
            }
            return false;
        }
    }
}