import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.Type;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.InsnList;
import jdk.internal.org.objectweb.asm.tree.MethodInsnNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import jdk.internal.org.objectweb.asm.tree.VarInsnNode;
import jdk.internal.org.objectweb.asm.tree.InsnNode;

public final class PatchCgn {
    private static final String TARGET = "burp/BurpExtender.class";
    private static final String ENHANCEMENT = "burp/CgnEnhancement.class";

    private PatchCgn() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("Usage: PatchCgn <input.jar> <CgnEnhancement.class> <output.jar>");
        }
        Path input = Path.of(args[0]);
        Path enhancementClass = Path.of(args[1]);
        Path output = Path.of(args[2]);
        byte[] enhancement = Files.readAllBytes(enhancementClass);
        Path temporary = output.resolveSibling(output.getFileName() + ".tmp");
        Files.deleteIfExists(temporary);

        try (JarFile source = new JarFile(input.toFile());
             OutputStream rawOut = Files.newOutputStream(temporary);
             JarOutputStream destination = new JarOutputStream(rawOut, manifestOrDefault(source))) {
            Enumeration<JarEntry> entries = source.entries();
            boolean patched = false;
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if ("META-INF/MANIFEST.MF".equalsIgnoreCase(entry.getName()) || ENHANCEMENT.equals(entry.getName())) {
                    continue;
                }
                JarEntry outputEntry = new JarEntry(entry.getName());
                outputEntry.setTime(entry.getTime());
                destination.putNextEntry(outputEntry);
                try (InputStream in = source.getInputStream(entry)) {
                    if (TARGET.equals(entry.getName())) {
                        destination.write(patchExtender(in.readAllBytes()));
                        patched = true;
                    } else {
                        in.transferTo(destination);
                    }
                }
                destination.closeEntry();
            }
            if (!patched) {
                throw new IOException("Missing " + TARGET);
            }
            JarEntry enhancementEntry = new JarEntry(ENHANCEMENT);
            destination.putNextEntry(enhancementEntry);
            destination.write(enhancement);
            destination.closeEntry();
        }
        Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static Manifest manifestOrDefault(JarFile source) throws IOException {
        Manifest manifest = source.getManifest();
        return manifest == null ? new Manifest() : manifest;
    }

    private static byte[] patchExtender(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode();
        reader.accept(node, 0);

        boolean registerRenamed = false;
        boolean unloadRenamed = false;
        boolean processRenamed = false;
        boolean passiveRenamed = false;
        boolean activeRenamed = false;
        boolean matchRenamed = false;
        boolean filterRenamed = false;
        boolean tableRefreshRenamed = false;
        for (MethodNode method : node.methods) {
            if ("registerExtenderCallbacks".equals(method.name)
                    && "(Lburp/IBurpExtenderCallbacks;)V".equals(method.desc)) {
                method.name = "cgn$registerExtenderCallbacksLegacy";
                registerRenamed = true;
            } else if ("extensionUnloaded".equals(method.name)
                    && "()V".equals(method.desc)) {
                method.name = "cgn$extensionUnloadedLegacy";
                unloadRenamed = true;
            } else if ("processHttpMessage".equals(method.name)
                    && "(IZLburp/IHttpRequestResponse;)V".equals(method.desc)) {
                method.name = "cgn$processHttpMessageLegacy";
                processRenamed = true;
            } else if ("doPassiveScan".equals(method.name)
                    && "(Lburp/IHttpRequestResponse;)Ljava/util/List;".equals(method.desc)) {
                method.name = "cgn$doPassiveScanHighMedium";
                passiveRenamed = true;
            } else if ("doActiveScan".equals(method.name)
                    && "(Lburp/IHttpRequestResponse;Lburp/IScannerInsertionPoint;)Ljava/util/List;".equals(method.desc)) {
                method.name = "cgn$doActiveScanLegacy";
                activeRenamed = true;
            } else if ("matchesFingerprintKeywords".equals(method.name)
                    && "(Ljava/lang/String;Ljava/lang/String;)Z".equals(method.desc)) {
                method.name = "cgn$matchesFingerprintKeywordsLegacy";
                matchRenamed = true;
            } else if ("scan_uri_filter".equals(method.name) && "()V".equals(method.desc)) {
                method.name = "cgn$scanUriFilterLegacy";
                filterRenamed = true;
            } else if ("fireScanTableChanged".equals(method.name) && "()V".equals(method.desc)) {
                method.name = "cgn$fireScanTableChangedLegacy";
                tableRefreshRenamed = true;
            }
        }
        if (!registerRenamed || !unloadRenamed || !processRenamed || !passiveRenamed
                || !activeRenamed || !matchRenamed || !filterRenamed || !tableRefreshRenamed) {
            throw new IllegalStateException("Expected methods were not found; source JAR may be incompatible.");
        }

        node.methods.add(wrapperRegister());
        node.methods.add(wrapperUnload());
        node.methods.add(wrapperProcess());
        node.methods.add(wrapperPassive());
        node.methods.add(wrapperActive());
        node.methods.add(wrapperMatcher());
        node.methods.add(wrapperScanUriFilter());
        node.methods.add(wrapperFireScanTableChanged());

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static MethodNode wrapperRegister() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "registerExtenderCallbacks",
                "(Lburp/IBurpExtenderCallbacks;)V", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ALOAD, 1));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement",
                "registerExtenderCallbacks",
                "(Lburp/BurpExtender;Lburp/IBurpExtenderCallbacks;)V", false));
        code.add(new InsnNode(Opcodes.RETURN));
        return method;
    }

    private static MethodNode wrapperUnload() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "extensionUnloaded", "()V", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement",
                "extensionUnloaded", "(Lburp/BurpExtender;)V", false));
        code.add(new InsnNode(Opcodes.RETURN));
        return method;
    }

    private static MethodNode wrapperProcess() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "processHttpMessage",
                "(IZLburp/IHttpRequestResponse;)V", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ILOAD, 1));
        code.add(new VarInsnNode(Opcodes.ILOAD, 2));
        code.add(new VarInsnNode(Opcodes.ALOAD, 3));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement", "processHttpMessage",
                "(Lburp/BurpExtender;IZLburp/IHttpRequestResponse;)V", false));
        code.add(new InsnNode(Opcodes.RETURN));
        return method;
    }

    private static MethodNode wrapperPassive() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "doPassiveScan",
                "(Lburp/IHttpRequestResponse;)Ljava/util/List;", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ALOAD, 1));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement", "doPassiveScan",
                "(Lburp/BurpExtender;Lburp/IHttpRequestResponse;)Ljava/util/List;", false));
        code.add(new InsnNode(Opcodes.ARETURN));
        return method;
    }

    private static MethodNode wrapperActive() {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "doActiveScan",
                "(Lburp/IHttpRequestResponse;Lburp/IScannerInsertionPoint;)Ljava/util/List;", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new VarInsnNode(Opcodes.ALOAD, 1));
        code.add(new VarInsnNode(Opcodes.ALOAD, 2));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement", "doActiveScan",
                "(Lburp/BurpExtender;Lburp/IHttpRequestResponse;Lburp/IScannerInsertionPoint;)Ljava/util/List;", false));
        code.add(new InsnNode(Opcodes.ARETURN));
        return method;
    }

    private static MethodNode wrapperMatcher() {
        MethodNode method = new MethodNode(Opcodes.ACC_PRIVATE, "matchesFingerprintKeywords",
                "(Ljava/lang/String;Ljava/lang/String;)Z", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 1));
        code.add(new VarInsnNode(Opcodes.ALOAD, 2));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement", "matchesFingerprintKeywords",
                "(Ljava/lang/String;Ljava/lang/String;)Z", false));
        code.add(new InsnNode(Opcodes.IRETURN));
        return method;
    }

    private static MethodNode wrapperScanUriFilter() {
        MethodNode method = new MethodNode(Opcodes.ACC_PRIVATE, "scan_uri_filter", "()V", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement", "scanUriFilter",
                "(Lburp/BurpExtender;)V", false));
        code.add(new InsnNode(Opcodes.RETURN));
        return method;
    }

    private static MethodNode wrapperFireScanTableChanged() {
        MethodNode method = new MethodNode(Opcodes.ACC_PRIVATE, "fireScanTableChanged", "()V", null, null);
        InsnList code = method.instructions;
        code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "burp/CgnEnhancement", "fireScanTableChanged",
                "(Lburp/BurpExtender;)V", false));
        code.add(new InsnNode(Opcodes.RETURN));
        return method;
    }
}
