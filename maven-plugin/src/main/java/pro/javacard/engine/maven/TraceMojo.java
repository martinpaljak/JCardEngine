// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.maven;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import pro.javacard.engine.CommentTrace;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

// Rewrites the compiled classes with the CommentTrace attribute, in place by default, after the CAP
// converter has had its turn and before the jar is built.
@Mojo(name = "trace", defaultPhase = LifecyclePhase.PREPARE_PACKAGE, threadSafe = true)
public class TraceMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project.build.outputDirectory}", property = "jcardengine.trace.classes")
    private File classes;

    // Defaults to the classes directory itself
    @Parameter(property = "jcardengine.trace.output")
    private File output;

    @Parameter(defaultValue = "${project.compileSourceRoots}")
    private List<String> sources;

    @Parameter(property = "jcardengine.trace.skip", defaultValue = "false")
    private boolean skip;

    @Parameter(defaultValue = "${project.build.sourceEncoding}")
    private String encoding;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip || !classes.isDirectory()) {
            getLog().info("Comment trace skipped");
            return;
        }
        Path out = (output == null ? classes : output).toPath();
        var charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
        try {
            CommentTrace.instrument(classes.toPath(), sources.stream().map(Path::of).toList(), out, charset, getLog()::info);
        } catch (IOException | RuntimeException e) {
            throw new MojoExecutionException("Comment trace failed: " + e.getMessage(), e);
        }
        getLog().info("Comment trace written to " + out);
    }
}
