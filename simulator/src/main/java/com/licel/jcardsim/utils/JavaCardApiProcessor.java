/*
 * Copyright 2015 Licel Corporation.
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
package com.licel.jcardsim.utils;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InnerClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Injects jCardSim’s code into Java Card Api Reference Classes
 */
public class JavaCardApiProcessor {

    public static void main(String args[]) throws Exception {
        File buildDir = new File(args[0]);
        if (!buildDir.exists() || !buildDir.isDirectory()) {
            throw new RuntimeException("Invalid directory: " + buildDir);
        }
        System.out.println("Processing " + buildDir);
        // NOTE: resorting to string here is intentional, as the transformation fscks up the class directory (proxies are removed)
        // This makes IDE very unhappy when running tests. Alternative: don't delete proxies (but removing them from dist would mean they all should live
        // in a separate package)
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.AIDProxy", "javacard.framework.AID", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.APDUProxy", "javacard.framework.APDU", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.AppletProxy", "javacard.framework.Applet", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.JCSystemProxy", "javacard.framework.JCSystem", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.UtilProxy", "javacard.framework.Util", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.OwnerPINProxy", "javacard.framework.OwnerPIN", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.security.ChecksumProxy", "javacard.security.Checksum", true);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.security.KeyAgreementProxy", "javacard.security.KeyAgreement", true);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.security.KeyPairProxy", "javacard.security.KeyPair", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.security.KeyBuilderProxy", "javacard.security.KeyBuilder", true);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.security.MessageDigestProxy", "javacard.security.MessageDigest", true);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.security.RandomDataProxy", "javacard.security.RandomData", true);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.security.SignatureProxy", "javacard.security.Signature", true);

        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.CardExceptionProxy", "javacard.framework.CardException", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacard.framework.CardRuntimeExceptionProxy", "javacard.framework.CardRuntimeException", false);

        proxyClass(buildDir, "pro.javacard.engine.proxy.javacardx.security.SensitiveResultProxy", "javacardx.security.SensitiveResult", false);
        proxyClass(buildDir, "pro.javacard.engine.proxy.javacardx.crypto.CipherProxy", "javacardx.crypto.Cipher", true);


        proxyExceptionClass(buildDir, "javacard.framework.APDUException");
        proxyExceptionClass(buildDir, "javacard.framework.ISOException");
        proxyExceptionClass(buildDir, "javacard.framework.PINException");
        proxyExceptionClass(buildDir, "javacard.framework.SystemException");
        proxyExceptionClass(buildDir, "javacard.framework.TransactionException");
        proxyExceptionClass(buildDir, "javacard.framework.UserException");
        proxyExceptionClass(buildDir, "javacard.framework.service.ServiceException");
        proxyExceptionClass(buildDir, "javacard.security.CryptoException");
        proxyExceptionClass(buildDir, "javacardx.external.ExternalException");
        proxyExceptionClass(buildDir, "javacardx.framework.tlv.TLVException");
        proxyExceptionClass(buildDir, "javacardx.biometry1toN.Bio1toNException");
        proxyExceptionClass(buildDir, "javacardx.framework.util.UtilException");
        proxyExceptionClass(buildDir, "javacardx.biometry.BioException");
        proxyExceptionClass(buildDir, "javacardx.framework.string.StringException");

        // Global Platform
        proxyClass(buildDir, "pro.javacard.engine.proxy.org.globalplatform.GPSystemProxy", "org.globalplatform.GPSystem", false);
    }

    public static void proxyClass(File buildDir, Class<?> proxyClass, Class<?> targetClass, boolean skipConstructor) throws IOException {
        proxyClass(buildDir, proxyClass.getName(), targetClass.getName(), skipConstructor, null);
    }

    public static void proxyClass(File buildDir, String proxyClassName, String targetClassName, boolean skipConstructor) throws IOException {
        proxyClass(buildDir, proxyClassName, targetClassName, skipConstructor, null);
    }

    public static void proxyClass(File buildDir, String proxyClassName, String targetClassName, boolean skipConstructor, Map<String, String> map) throws IOException {
        System.out.println("Proxying " + proxyClassName + " to " + targetClassName);
        File proxyFile = new File(buildDir, proxyClassName.replace(".", File.separator) + ".class");
        FileInputStream fProxyClass = new FileInputStream(proxyFile);
        FileInputStream fTargetClass = new FileInputStream(new File(buildDir, targetClassName.replace(".", File.separator) + ".class"));
        ClassReader crProxy = new ClassReader(fProxyClass);
        ClassNode cnProxy = new ClassNode();
        crProxy.accept(cnProxy, 0);
        ClassReader crTarget = new ClassReader(fTargetClass);
        ClassNode cnTarget = new ClassNode();
        crTarget.accept(cnTarget, 0);

        ClassNode cnProxyRemapped = new ClassNode();
        Map<String, String> mapping = map == null ? new HashMap<>() : new HashMap<>(map);
        mapping.put(cnProxy.name, cnTarget.name);

        if (map == null) {
            // Map inner classes in addition to the enclosing class
            if (cnProxy.innerClasses != null) {
                for (InnerClassNode innerClass : cnProxy.innerClasses) {
                    if (innerClass.name.startsWith(cnProxy.name + "$")) {
                        String innerClassName = innerClass.name.substring(cnProxy.name.length());
                        mapping.put(cnProxy.name + innerClassName, cnTarget.name + innerClassName);
                        System.out.println("Mapping " + cnProxy.name + innerClassName + " to " + cnTarget.name + innerClassName);
                    }
                }
            }

            // Process separate inner class files, with the existing mapping context
            if (cnProxy.innerClasses != null) {
                for (InnerClassNode innerClass : cnProxy.innerClasses) {
                    if (innerClass.name.startsWith(cnProxy.name + "$")) {
                        String innerClassName = innerClass.name.substring(cnProxy.name.length());
                        // At this point this only applies to OneShot, so do not skip constructor.
                        proxyClass(buildDir, cnProxy.name + innerClassName, cnTarget.name + innerClassName, false, mapping);
                    }
                }
            }
        }

        ClassRemapper ra = new ClassRemapper(cnProxyRemapped, new SimpleRemapper(mapping));
        cnProxy.accept(ra);

        ClassWriter cw = new ClassWriter(crTarget, ClassWriter.COMPUTE_FRAMES);
        MergeAdapter ma = new MergeAdapter(cw, cnProxyRemapped, skipConstructor);
        cnTarget.accept(ma);
        fProxyClass.close();
        fTargetClass.close();
        FileOutputStream fos = new FileOutputStream(new File(buildDir, targetClassName.replace(".", File.separator) + ".class"));
        fos.write(cw.toByteArray());
        fos.close();
        // remove proxy class
        if (!proxyFile.delete()) {
            System.err.println("Could not delete " + proxyFile.getAbsolutePath());
        }
    }

    public static void proxyExceptionClass(File buildDir, String targetClassName) throws IOException {
        FileInputStream fTargetClass = new FileInputStream(new File(buildDir, targetClassName.replace(".", File.separator) + ".class"));
        ClassReader crTarget = new ClassReader(fTargetClass);
        ClassNode cnTarget = new ClassNode();
        crTarget.accept(cnTarget, 0);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        ExceptionClassProxy ecc = new ExceptionClassProxy(cw, cnTarget.version, cnTarget.name, cnTarget.superName);
        cnTarget.accept(ecc);

        fTargetClass.close();
        FileOutputStream fos = new FileOutputStream(new File(buildDir, targetClassName.replace(".", File.separator) + ".class"));
        fos.write(cw.toByteArray());
        fos.close();
    }

    static class ExceptionClassProxy extends ClassVisitor implements Opcodes {

        String superClassName;
        String className;

        public ExceptionClassProxy(ClassWriter cv, int classVersion, String exceptionClassName, String superClassName) {
            super(ASM9, cv);
            this.superClassName = superClassName;
            this.className = exceptionClassName;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            return null;
        }

        @Override
        public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
            // skip jc 2.2.2 api impl
            if ((access & ACC_PUBLIC) != ACC_PUBLIC) {
                System.out.println("Ignoring exception field " + name);
                return null;
            }
            return super.visitField(access, name, desc, signature, value);
        }

        @Override
        public void visitEnd() {
            // ASM for adding the body to constructor and static throwIt, resulting in:
            // public class YourClassName extends YourSuperClass {
            //    public YourClassName(short value) {
            //        super(value);
            //    }
            //    public static void throwIt(short value) {
            //        throw new YourClassName(value);
            //    }
            //}

            MethodVisitor mv = cv.visitMethod(ACC_PUBLIC, "<init>", "(S)V", null, null);
            mv.visitCode();
            mv.visitVarInsn(ALOAD, 0);
            mv.visitVarInsn(ILOAD, 1);
            mv.visitMethodInsn(INVOKESPECIAL, superClassName, "<init>", "(S)V", false);
            mv.visitInsn(RETURN);
            mv.visitMaxs(2, 2);
            mv.visitEnd();
            mv = cv.visitMethod(ACC_PUBLIC + ACC_STATIC, "throwIt", "(S)V", null, null);
            mv.visitCode();
            mv.visitTypeInsn(NEW, className);
            mv.visitInsn(DUP);
            mv.visitVarInsn(ILOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, className, "<init>", "(S)V", false);
            mv.visitInsn(ATHROW);
            mv.visitMaxs(3, 1);
            mv.visitEnd();
        }

    }

    static class ClassAdapter extends ClassNode implements Opcodes {

        public ClassAdapter(ClassVisitor cv) {
            super(ASM9);
            this.cv = cv;
        }

        @Override
        public void visitEnd() {
            accept(cv);
        }
    }

    static class MergeAdapter extends ClassAdapter {

        private ClassNode cn;
        private String cname;
        private HashMap<String, MethodNode> cnMethods = new HashMap<>();
        private HashMap<String, FieldNode> cnFields = new HashMap<>();
        private boolean skipConstructor;

        public MergeAdapter(ClassVisitor cv, ClassNode cn, boolean skipConstructor) {
            super(cv);
            this.cn = cn;
            this.skipConstructor = skipConstructor;
            for (MethodNode mn : cn.methods) {
                if (skipConstructor && mn.name.equals("<init>")) {
                    continue;
                }
                cnMethods.put(mn.name + mn.desc, mn);
            }
            for (FieldNode fn : cn.fields) {
                cnFields.put(fn.name + fn.desc, fn);
            }
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.cname = name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            if (cnMethods.containsKey(name + desc) || ((access & (ACC_PUBLIC | ACC_PROTECTED)) == 0)) {
                //System.out.println("Use proxy method:    " + cname + "::" + name + desc);
                return null;
            }
            System.err.println("Uses original method: " + cname + "::" + name + desc);
            return super.visitMethod(access, name, desc, signature, exceptions);
        }

        @Override
        public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
            // skip jc 2.2.2 api impl
            if ((access & ACC_PUBLIC) != ACC_PUBLIC) {
                System.out.println("skip field: " + cname + name + desc);
                return null;
            }
            return super.visitField(access, name, desc, signature, value);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
            for (FieldNode fn : cn.fields) {
                cv.visitField(fn.access, fn.name, fn.desc, fn.signature, fn.value);
            }
            for (MethodNode mn : cn.methods) {
                if (skipConstructor && mn.name.equals("<init>")) {
                    continue;
                }
                String[] exceptions = new String[mn.exceptions.size()];
                mn.exceptions.toArray(exceptions);
                MethodVisitor mv = cv.visitMethod(mn.access, mn.name, mn.desc, mn.signature, exceptions);
                mn.instructions.resetLabels();
                mn.accept(mv);
            }
        }
    }
}
