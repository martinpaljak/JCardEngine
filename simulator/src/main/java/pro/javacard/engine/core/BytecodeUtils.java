package pro.javacard.engine.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class BytecodeUtils {
    private static final Logger log = LoggerFactory.getLogger(BytecodeUtils.class);

    public static byte[] transform(byte[] classBytes, ClassLoader classLoader) {

        ClassReader classReader = new ClassReader(classBytes);
        ClassWriter classWriter = new CustomClassWriter(classReader, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, classLoader);

        MemoryAllocationInterceptor interceptor = new MemoryAllocationInterceptor(classWriter);
        //classReader.accept(interceptor, 0);
        FaultInjectionInterceptor other = new FaultInjectionInterceptor(interceptor);
        classReader.accept(other, 0);

        return classWriter.toByteArray();
    }

    // Custom ClassWriter that uses the correct ClassLoader
    static class CustomClassWriter extends ClassWriter {
        private final ClassLoader classLoader;

        public CustomClassWriter(ClassReader classReader, int flags, ClassLoader classLoader) {
            super(classReader, flags);
            this.classLoader = classLoader == null ? super.getClassLoader() : classLoader;
        }

        @Override
        protected ClassLoader getClassLoader() {
            return classLoader;
        }
    }
}
