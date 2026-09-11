// Detailed headless export for native ELF libraries.
// @category MobileGhidraLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedDataIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExportAnalysis extends GhidraScript {

    private File outDir;
    private int functionCount = 0;
    private int symbolCount = 0;
    private int stringCount = 0;
    private int callEdgeCount = 0;
    private int decompiledCount = 0;
    private int decompileFailureCount = 0;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("ExportAnalysis.java requires output directory argument");
        }

        outDir = new File(args[0]);
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IllegalStateException("Could not create output directory: " + outDir);
        }

        int maxDecompileFunctions = args.length >= 2 ? parseInt(args[1], 2500) : 2500;
        int totalBudgetSeconds = args.length >= 3 ? parseInt(args[2], 1200) : 1200;
        int perFunctionTimeoutSeconds = args.length >= 4 ? parseInt(args[3], 8) : 8;

        println("[mobile-ghidra-lab] Exporting analysis to " + outDir.getAbsolutePath());

        exportProgramMetadata();
        exportFunctions();
        exportSymbols();
        exportStringsAndXrefs();
        exportCallGraph();
        exportDisassembly();
        exportDecompiler(maxDecompileFunctions, totalBudgetSeconds, perFunctionTimeoutSeconds);
        exportJniCandidates();
        exportSummary(maxDecompileFunctions, totalBudgetSeconds, perFunctionTimeoutSeconds);

        println("[mobile-ghidra-lab] Export complete");
    }

    private void exportProgramMetadata() throws Exception {
        try (PrintWriter w = writer("ghidra_program.json")) {
            w.println("{");
            w.println("  \"name\": \"" + json(currentProgram.getName()) + "\",");
            w.println("  \"executable_format\": \"" + json(currentProgram.getExecutableFormat()) + "\",");
            w.println("  \"executable_path\": \"" + json(currentProgram.getExecutablePath()) + "\",");
            w.println("  \"md5\": \"" + json(currentProgram.getExecutableMD5()) + "\",");
            w.println("  \"sha256\": \"" + json(currentProgram.getExecutableSHA256()) + "\",");
            w.println("  \"image_base\": \"" + currentProgram.getImageBase() + "\",");
            w.println("  \"language\": \"" + json(currentProgram.getLanguageID().toString()) + "\",");
            w.println("  \"compiler_spec\": \"" + json(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\",");
            w.println("  \"address_size_bits\": " + currentProgram.getAddressFactory().getDefaultAddressSpace().getSize());
            w.println("}");
        }
    }

    private void exportFunctions() throws Exception {
        try (PrintWriter w = writer("functions.csv")) {
            w.println("entry,name,namespace,size_bytes,parameter_count,calling_convention,is_thunk,is_external,signature");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                functionCount++;
                String ns = f.getParentNamespace() == null ? "" : f.getParentNamespace().getName();
                String sig;
                try {
                    sig = f.getSignature().toString();
                } catch (Exception e) {
                    sig = "";
                }
                w.println(csv(f.getEntryPoint().toString()) + "," +
                    csv(f.getName()) + "," +
                    csv(ns) + "," +
                    f.getBody().getNumAddresses() + "," +
                    f.getParameterCount() + "," +
                    csv(f.getCallingConventionName()) + "," +
                    f.isThunk() + "," +
                    f.isExternal() + "," +
                    csv(sig));
            }
        }
    }

    private void exportSymbols() throws Exception {
        try (PrintWriter w = writer("symbols.csv")) {
            w.println("address,name,type,source,namespace,primary");
            SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                symbolCount++;
                String ns = s.getParentNamespace() == null ? "" : s.getParentNamespace().getName();
                w.println(csv(s.getAddress().toString()) + "," +
                    csv(s.getName()) + "," +
                    csv(s.getSymbolType().toString()) + "," +
                    csv(s.getSource().toString()) + "," +
                    csv(ns) + "," +
                    s.isPrimary());
            }
        }
    }

    private void exportStringsAndXrefs() throws Exception {
        try (PrintWriter strings = writer("strings.csv");
             PrintWriter xrefs = writer("string_xrefs.csv")) {
            strings.println("address,length,value");
            xrefs.println("string_address,from_address,from_function,reference_type,value");

            for (Data d : DefinedDataIterator.definedStrings(currentProgram)) {
                if (monitor.isCancelled()) break;
                stringCount++;
                String value = d.getDefaultValueRepresentation();
                if (value == null) value = "";
                if (value.length() > 4096) value = value.substring(0, 4096) + "...[truncated]";
                strings.println(csv(d.getAddress().toString()) + "," + d.getLength() + "," + csv(value));

                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function from = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    xrefs.println(csv(d.getAddress().toString()) + "," +
                        csv(ref.getFromAddress().toString()) + "," +
                        csv(from == null ? "" : from.getName()) + "," +
                        csv(ref.getReferenceType().toString()) + "," +
                        csv(value));
                }
            }
        }
    }

    private void exportCallGraph() throws Exception {
        try (PrintWriter w = writer("callgraph.csv")) {
            w.println("caller_entry,caller_name,callsite,callee_entry,callee_name,reference_type");
            InstructionIterator it = currentProgram.getListing().getInstructions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Instruction ins = it.next();
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
                if (caller == null) continue;
                Reference[] refs = ins.getReferencesFrom();
                for (Reference ref : refs) {
                    if (!ref.getReferenceType().isCall()) continue;
                    Function callee = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (callee == null) {
                        callee = currentProgram.getFunctionManager().getFunctionContaining(ref.getToAddress());
                    }
                    callEdgeCount++;
                    w.println(csv(caller.getEntryPoint().toString()) + "," +
                        csv(caller.getName()) + "," +
                        csv(ins.getAddress().toString()) + "," +
                        csv(callee == null ? ref.getToAddress().toString() : callee.getEntryPoint().toString()) + "," +
                        csv(callee == null ? "<unresolved>" : callee.getName()) + "," +
                        csv(ref.getReferenceType().toString()));
                }
            }
        }
    }

    private void exportDisassembly() throws Exception {
        try (PrintWriter w = writer("disassembly.txt")) {
            InstructionIterator it = currentProgram.getListing().getInstructions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Instruction ins = it.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
                String fn = f == null ? "" : f.getName();
                w.printf("%s\t%-36s\t%s%n", ins.getAddress(), fn, ins.toString());
            }
        }
    }

    private void exportDecompiler(int maxFunctions, int totalBudgetSeconds, int perFunctionTimeoutSeconds) throws Exception {
        List<Function> funcs = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (!f.isExternal()) funcs.add(f);
        }

        Collections.sort(funcs, new Comparator<Function>() {
            @Override
            public int compare(Function a, Function b) {
                int pa = priority(a);
                int pb = priority(b);
                if (pa != pb) return Integer.compare(pb, pa);
                int sizeCmp = Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses());
                if (sizeCmp != 0) return sizeCmp;
                return a.getEntryPoint().compareTo(b.getEntryPoint());
            }
        });

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(currentProgram)) {
            try (PrintWriter w = writer("decompiler_error.txt")) {
                w.println("Unable to initialize Ghidra decompiler: " + decompiler.getLastMessage());
            }
            decompiler.dispose();
            return;
        }

        long started = System.nanoTime();
        long budgetNanos = Math.max(30, totalBudgetSeconds) * 1_000_000_000L;

        try (PrintWriter code = writer("decompiled.c");
             PrintWriter index = writer("decompiled_index.csv")) {
            index.println("entry,name,size_bytes,status,error");
            int attempted = 0;
            for (Function f : funcs) {
                if (monitor.isCancelled()) break;
                if (attempted >= maxFunctions) break;
                if ((System.nanoTime() - started) >= budgetNanos) break;
                if (f.isThunk() && isDefaultName(f.getName())) continue;

                attempted++;
                try {
                    DecompileResults r = decompiler.decompileFunction(f, perFunctionTimeoutSeconds, monitor);
                    if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                        String c = r.getDecompiledFunction().getC();
                        code.println("\n/* ========================================================================");
                        code.println(" * " + f.getEntryPoint() + "  " + f.getName());
                        code.println(" * size=" + f.getBody().getNumAddresses() + " bytes");
                        code.println(" * ======================================================================== */");
                        code.println(c);
                        decompiledCount++;
                        index.println(csv(f.getEntryPoint().toString()) + "," + csv(f.getName()) + "," +
                            f.getBody().getNumAddresses() + ",ok,");
                    } else {
                        decompileFailureCount++;
                        String err = r == null ? "null result" : r.getErrorMessage();
                        index.println(csv(f.getEntryPoint().toString()) + "," + csv(f.getName()) + "," +
                            f.getBody().getNumAddresses() + ",failed," + csv(err));
                    }
                } catch (Exception e) {
                    decompileFailureCount++;
                    index.println(csv(f.getEntryPoint().toString()) + "," + csv(f.getName()) + "," +
                        f.getBody().getNumAddresses() + ",exception," + csv(e.toString()));
                }
            }
        } finally {
            decompiler.dispose();
        }
    }

    private void exportJniCandidates() throws Exception {
        Set<String> seen = new HashSet<>();
        try (PrintWriter w = writer("jni_candidates.txt")) {
            w.println("# Functions and symbols whose names suggest JNI/native registration relevance");
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext()) {
                Function f = fit.next();
                String n = f.getName();
                if (looksJniRelated(n)) {
                    String line = f.getEntryPoint() + "\tFUNCTION\t" + n;
                    if (seen.add(line)) w.println(line);
                }
            }
            SymbolIterator sit = currentProgram.getSymbolTable().getAllSymbols(true);
            while (sit.hasNext()) {
                Symbol s = sit.next();
                String n = s.getName();
                if (looksJniRelated(n)) {
                    String line = s.getAddress() + "\tSYMBOL\t" + n;
                    if (seen.add(line)) w.println(line);
                }
            }
        }
    }

    private void exportSummary(int maxFunctions, int budgetSeconds, int perFunctionTimeoutSeconds) throws Exception {
        try (PrintWriter w = writer("analysis_summary.md")) {
            w.println("# Ghidra analysis summary");
            w.println();
            w.println("- Program: `" + currentProgram.getName() + "`");
            w.println("- Format: `" + currentProgram.getExecutableFormat() + "`");
            w.println("- Language: `" + currentProgram.getLanguageID() + "`");
            w.println("- Compiler spec: `" + currentProgram.getCompilerSpec().getCompilerSpecID() + "`");
            w.println("- Image base: `" + currentProgram.getImageBase() + "`");
            w.println("- SHA-256: `" + currentProgram.getExecutableSHA256() + "`");
            w.println("- Functions discovered: **" + functionCount + "**");
            w.println("- Symbols exported: **" + symbolCount + "**");
            w.println("- Defined strings exported: **" + stringCount + "**");
            w.println("- Call edges exported: **" + callEdgeCount + "**");
            w.println("- Functions decompiled successfully: **" + decompiledCount + "**");
            w.println("- Decompile failures/timeouts: **" + decompileFailureCount + "**");
            w.println();
            w.println("## Decompiler limits for this run");
            w.println();
            w.println("- Maximum candidate functions: " + maxFunctions);
            w.println("- Total decompile budget: " + budgetSeconds + " seconds");
            w.println("- Per-function timeout: " + perFunctionTimeoutSeconds + " seconds");
            w.println();
            w.println("The function inventory, symbols, strings, call graph and disassembly are exported independently of the pseudocode budget.");
            w.println("Pseudocode is an inference made by Ghidra and is not the original C/C++ source code.");
        }
    }

    private int priority(Function f) {
        String n = f.getName();
        int p = 0;
        if (looksJniRelated(n)) p += 1000;
        if (!isDefaultName(n)) p += 500;
        if (!f.isThunk()) p += 100;
        long sz = f.getBody().getNumAddresses();
        p += (int) Math.min(200, sz / 32);
        return p;
    }

    private boolean looksJniRelated(String s) {
        if (s == null) return false;
        String n = s.toLowerCase();
        return n.contains("jni_onload") || n.startsWith("java_") || n.contains("registernatives") ||
               n.contains("jnienv") || n.contains("native") || n.contains("jni");
    }

    private boolean isDefaultName(String s) {
        if (s == null) return true;
        return s.matches("FUN_[0-9a-fA-F]+") || s.matches("thunk_FUN_[0-9a-fA-F]+") ||
               s.matches("LAB_[0-9a-fA-F]+") || s.matches("SUB_[0-9a-fA-F]+");
    }

    private int parseInt(String s, int fallback) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return fallback;
        }
    }

    private PrintWriter writer(String name) throws Exception {
        return new PrintWriter(new BufferedWriter(new OutputStreamWriter(
            new FileOutputStream(new File(outDir, name)), StandardCharsets.UTF_8)), true);
    }

    private String csv(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\"", "\"\"").replace("\r", " ").replace("\n", "\\n") + "\"";
    }

    private String json(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
}
