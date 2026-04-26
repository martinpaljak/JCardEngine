// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Analyzes bytecode to find all packages referenced by a class and its same-package dependencies. Uses ASM to extract
 * type references from signatures, fields, methods, and method bodies. Recursively follows same-package classes to
 * capture the full applet codebase while only recording package names for external dependencies. Returns all
 * referenced packages except the entry class's own.
 */
public class DependencyAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(DependencyAnalyzer.class);

    public static Set<String> getAllPackages(Class<?> someClass) {
        Set<String> packages = new LinkedHashSet<>();
        Set<String> visited = new HashSet<>();
        try {
            collectPackages(someClass.getName(), someClass.getClassLoader(), packages, visited);
        } catch (IOException e) {
            log.error("Failed to collect packages for {}", someClass.getName(), e);
        }
        // We are not interested in the package of the class itself.
        packages.remove(someClass.getPackageName());
        return packages;
    }

    private static void collectPackages(String className, ClassLoader classLoader, Set<String> packages, Set<String> visited) throws IOException {
        String pkg = getPackage(className);
        if (visited.contains(className) || pkg == null) {
            return;
        }
        visited.add(className);

        byte[] classBytes = getClassBytes(className, classLoader);
        if (classBytes == null) {
            log.debug("Class not found: {}", className);
            // Can't load it - just record the package reference
            packages.add(pkg);
            return;
        }

        packages.add(pkg);

        Set<String> deps = new HashSet<>();
        new ClassReader(classBytes).accept(new DependencyVisitor(deps), ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        for (String dep : deps) {
            String depPkg = getPackage(dep);
            if (depPkg != null) {
                // Only recurse into classes from the SAME package (applet's own code)
                // For other packages, just record the package reference
                if (depPkg.equals(pkg)) {
                    collectPackages(dep, classLoader, packages, visited);
                } else {
                    packages.add(depPkg);
                }
            }
        }
    }

    private static String getPackage(String className) {
        int lastDot = className.lastIndexOf('.');
        return lastDot > 0 ? className.substring(0, lastDot) : null;
    }

    private static byte[] getClassBytes(String className, ClassLoader loader) throws IOException {
        String path = className.replace('.', '/') + ".class";
        try (InputStream is = loader.getResourceAsStream(path)) {
            return is == null ? null : is.readAllBytes();
        }
    }

    static class DependencyVisitor extends ClassVisitor {
        private final Set<String> deps;

        DependencyVisitor(Set<String> deps) {
            super(Opcodes.ASM9);
            this.deps = deps;
        }

        private void addType(String internalName) {
            if (internalName != null && internalName.contains("/")) {
                deps.add(internalName.replace('/', '.'));
            }
        }

        private void addDescriptor(Type type) {
            if (type.getSort() == Type.ARRAY) {
                addDescriptor(type.getElementType());
            } else if (type.getSort() == Type.OBJECT) {
                addType(type.getInternalName());
            }
        }

        @Override
        public void visit(int version, int access, String name, String sig, String superName, String[] interfaces) {
            addType(superName);
            if (interfaces != null) {
                for (String i : interfaces) {
                    addType(i);
                }
            }
        }

        @Override
        public FieldVisitor visitField(int access, String name, String desc, String sig, Object value) {
            addDescriptor(Type.getType(desc));
            return null;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            Type mt = Type.getMethodType(desc);
            addDescriptor(mt.getReturnType());
            for (Type t : mt.getArgumentTypes()) {
                addDescriptor(t);
            }

            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitTypeInsn(int op, String type) {
                    addType(type);
                }

                @Override
                public void visitFieldInsn(int op, String owner, String n, String desc) {
                    addType(owner);
                    addDescriptor(Type.getType(desc));
                }

                @Override
                public void visitMethodInsn(int op, String owner, String n, String desc, boolean itf) {
                    addType(owner);
                    Type mt = Type.getMethodType(desc);
                    addDescriptor(mt.getReturnType());
                    for (Type t : mt.getArgumentTypes()) {
                        addDescriptor(t);
                    }
                }

                @Override
                public void visitTryCatchBlock(Label s, Label e, Label h, String type) {
                    if (type != null) {
                        addType(type);
                    }
                }
            };
        }
    }
}