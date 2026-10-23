// Targeted exporter for Mobile Ghidra Lab: decompile ONLY the functions you ask for.
// Designed for the phone/CI workflow where a 100MB+ library makes the all-function pass
// cost hours. One import, one pass, small artifact.
// @category MobileGhidraLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportTargeted extends GhidraScript {

    private static class Spec {
        String raw;
        String kind;   // addr | rva | foff | name | regex
        String value;
        Spec(String raw, String kind, String value) { this.raw = raw; this.kind = kind; this.value = value; }
    }

    private File outDir;
    private File cDir;
    private File asmDir;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "ExportTargeted.java <outDir> <targetsFile> [timeoutSec] [maxFunctions] [budgetSec]");
        }
        outDir = new File(args[0]);
        File targetsFile = new File(args[1]);
        int timeoutSec = args.length >= 3 ? parseInt(args[2], 20) : 20;
        int maxFunctions = args.length >= 4 ? parseInt(args[3], 200) : 200;
        int budgetSec = args.length >= 5 ? parseInt(args[4], 1800) : 1800;

        cDir = new File(outDir, "targeted/c");
        asmDir = new File(outDir, "targeted/asm");
        cDir.mkdirs();
        asmDir.mkdirs();
        outDir.mkdirs();

        List<Spec> specs = readSpecs(targetsFile);
        println("[targeted] specs=" + specs.size() + " timeoutSec=" + timeoutSec
                + " maxFunctions=" + maxFunctions + " budgetSec=" + budgetSec
                + " imageBase=0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));

        DecompInterface d = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        d.setOptions(opts);
        d.toggleCCode(true);
        d.toggleSyntaxTree(false);
        d.setSimplificationStyle("decompile");
        if (!d.openProgram(currentProgram)) throw new IllegalStateException("decompiler openProgram failed");

        long start = System.currentTimeMillis();
        int total = 0, ok = 0, failed = 0, unresolved = 0;
        Set<Long> seen = new LinkedHashSet<>();
        try (PrintWriter idx = writer(new File(outDir, "targeted_index.csv"))) {
            idx.println("requested,resolved_entry,name,status,size_bytes,instructions,decompile_ms,c_file,asm_file,error");
            for (Spec s : specs) {
                if ((System.currentTimeMillis() - start) / 1000 > budgetSec) {
                    idx.println(csv(s.raw) + ",,,budget_exceeded,0,0,0,,,");
                    failed++;
                    continue;
                }
                if (total >= maxFunctions) {
                    idx.println(csv(s.raw) + ",,,max_functions_reached,0,0,0,,,");
                    failed++;
                    continue;
                }
                Function f = resolve(s);
                if (f == null) {
                    idx.println(csv(s.raw) + ",,,unresolved,0,0,0,,,");
                    unresolved++;
                    println("[targeted] UNRESOLVED " + s.raw);
                    continue;
                }
                long entry = f.getEntryPoint().getOffset();
                if (!seen.add(entry)) continue;
                total++;
                String addr = canon(f.getEntryPoint().toString());
                String name = displayName(f);
                long t0 = System.currentTimeMillis();
                String status = "failed", err = "", relC = "", relA = "";
                try {
                    DecompileResults r = d.decompileFunction(f, timeoutSec, monitor);
                    String c = (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                            ? r.getDecompiledFunction().getC() : null;
                    if (c != null && !c.trim().isEmpty()) {
                        File cf = new File(cDir, addr + "_" + sanitize(name) + ".c");
                        try (PrintWriter w = writer(cf)) {
                            w.println("/* targeted Ghidra decompilation; reconstruction, not original source */");
                            w.println("/* entry=0x" + addr + " name=" + name + " */");
                            w.println(c);
                        }
                        relC = "targeted/c/" + cf.getName();
                        status = "ok"; ok++;
                    } else {
                        err = clean(r == null ? "no_result" : r.getErrorMessage());
                        failed++;
                    }
                } catch (Exception ex) {
                    err = clean(ex.toString()); failed++;
                }
                long ms = System.currentTimeMillis() - t0;
                try {
                    File af = new File(asmDir, addr + "_" + sanitize(name) + ".asm");
                    int n = writeAsm(f, af);
                    relA = "targeted/asm/" + af.getName();
                    idx.println(String.join(",", csv(s.raw), csv(addr), csv(name), csv(status),
                            String.valueOf(f.getBody().getNumAddresses()), String.valueOf(n),
                            String.valueOf(ms), csv(relC), csv(relA), csv(err)));
                } catch (Exception ex) {
                    idx.println(String.join(",", csv(s.raw), csv(addr), csv(name), csv(status),
                            String.valueOf(f.getBody().getNumAddresses()), "0",
                            String.valueOf(ms), csv(relC), "", csv(clean(ex.toString()))));
                }
                idx.flush();
                println("[targeted] " + status + " 0x" + addr + " " + name + " (" + ms + " ms)");
            }
        } finally {
            d.dispose();
        }
        try (PrintWriter sum = writer(new File(outDir, "targeted/summary.txt"))) {
            sum.println("specs=" + specs.size());
            sum.println("resolved=" + total);
            sum.println("ok=" + ok);
            sum.println("failed=" + failed);
            sum.println("unresolved=" + unresolved);
            sum.println("elapsed_sec=" + (System.currentTimeMillis() - start) / 1000);
        }
        println("[targeted] complete ok=" + ok + " failed=" + failed + " unresolved=" + unresolved);
    }

    private List<Spec> readSpecs(File f) throws Exception {
        List<Spec> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String lower = line.toLowerCase();
                if (lower.startsWith("re:")) out.add(new Spec(line, "regex", line.substring(3)));
                else if (lower.startsWith("name:")) out.add(new Spec(line, "name", line.substring(5)));
                else if (lower.startsWith("rva:")) out.add(new Spec(line, "rva", line.substring(4)));
                else if (lower.startsWith("foff:")) out.add(new Spec(line, "foff", line.substring(5)));
                else out.add(new Spec(line, "addr", line));
            }
        }
        return out;
    }

    private Function resolve(Spec s) {
        try {
            switch (s.kind) {
                case "name":
                    return byName(s.value);
                case "regex":
                    return byRegex(s.value);
                case "rva":
                    return byAddress(currentProgram.getImageBase().add(Long.parseUnsignedLong(strip(s.value), 16)));
                case "foff": {
                    long off = Long.parseUnsignedLong(strip(s.value), 16);
                    long base = currentProgram.getImageBase().getOffset();
                    return byAddress(toAddr(base + off));
                }
                default:
                    return byAddress(parseAddr(s.value));
            }
        } catch (Exception e) {
            return null;
        }
    }

    private Function byAddress(Address a) {
        if (a == null) return null;
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f;
    }

    private Function byName(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (name.equals(f.getName())) return f;
        }
        return null;
    }

    private Function byRegex(String pattern) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (p.matcher(f.getName()).find()) return f;
        }
        return null;
    }

    private Address parseAddr(String s) {
        String v = strip(s);
        long off = Long.parseUnsignedLong(v, 16);
        Address a = toAddr(off);
        if (byAddress(a) != null) return a;
        Address shifted = toAddr(currentProgram.getImageBase().getOffset() + off);
        return byAddress(shifted) != null ? shifted : a;
    }

    private int writeAsm(Function f, File out) throws Exception {
        int n = 0;
        try (PrintWriter w = writer(out)) {
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Instruction ins = it.next();
                StringBuilder bytes = new StringBuilder();
                for (byte b : ins.getBytes()) bytes.append(String.format("%02x", b));
                w.println(ins.getAddress() + "  " + bytes + "  " + ins.toString());
                n++;
            }
        }
        return n;
    }

    private String displayName(Function f) {
        String n = f.getName();
        return (n == null || n.isEmpty()) ? "sub_" + canon(f.getEntryPoint().toString()) : n;
    }

    private String strip(String s) {
        String v = s.trim();
        if (v.toLowerCase().startsWith("0x")) v = v.substring(2);
        return v.replace("g:", "").replace("_", "");
    }

    private int parseInt(String s, int d) { try { return Integer.parseInt(s.trim()); } catch (Exception e) { return d; } }

    private String canon(String s) {
        s = s == null ? "" : s.trim();
        if (s.toLowerCase().startsWith("0x")) s = s.substring(2);
        try { return String.format("%08X", Long.parseUnsignedLong(s, 16)); } catch (Exception e) { return s.toUpperCase(); }
    }

    private String sanitize(String s) { return (s == null ? "fn" : s).replaceAll("[^A-Za-z0-9_.-]+", "_"); }

    private String clean(String s) { return s == null ? "" : s.replace('\n', ' ').replace('\r', ' ').trim(); }

    private String csv(String s) {
        s = s == null ? "" : s;
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }

    private PrintWriter writer(File f) throws Exception {
        File p = f.getParentFile();
        if (p != null) p.mkdirs();
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8));
    }
}
