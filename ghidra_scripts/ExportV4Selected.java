// Selective second-pass exporter for Mobile Ghidra Lab V4.
// @category MobileGhidraLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportV4Selected extends GhidraScript {

    private static class Target {
        String entry;
        String name;
        String mode;
        String score;
    }

    private File outDir;
    private File asmDir;
    private File decompDir;
    private File regionDir;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("ExportV4Selected.java <outDir> <selectionCsv> [budgetSec] [timeoutSec]");
        }
        outDir = new File(args[0]);
        File selection = new File(args[1]);
        int budgetSec = args.length >= 3 ? parseInt(args[2], 900) : 900;
        int timeoutSec = args.length >= 4 ? parseInt(args[3], 8) : 8;

        asmDir = new File(outDir, "v4_selected_ida");
        decompDir = new File(outDir, "v4_decompiled_selected");
        regionDir = new File(outDir, "v4_giant_regions");
        asmDir.mkdirs();
        decompDir.mkdirs();
        regionDir.mkdirs();

        List<Target> targets = readTargets(selection);
        println("[v4] selected targets=" + targets.size());

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("decompile");
        boolean decompilerReady = decompiler.openProgram(currentProgram);
        long started = System.nanoTime();
        long budgetNanos = Math.max(30, budgetSec) * 1_000_000_000L;

        try (PrintWriter index = writer(new File(outDir, "v4_selected_export.csv"));
             PrintWriter regionIndex = writer(new File(outDir, "v4_giant_region_index.csv"))) {
            index.println("entry,name,mode,score,size_bytes,instructions,decompile_status,asm_or_region_path");
            regionIndex.println("function_entry,function_name,region_id,center_address,reason,start_address,end_address,instructions,path");

            for (Target t : targets) {
                if (monitor.isCancelled()) break;
                Address a = parseTargetAddress(t.entry);
                Function f = a == null ? null : currentProgram.getFunctionManager().getFunctionAt(a);
                if (f == null && a != null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
                if (f == null) {
                    index.println(csv(t.entry) + "," + csv(t.name) + "," + csv(t.mode) + "," + csv(t.score) + ",0,0,missing,");
                    continue;
                }

                List<Instruction> ins = instructions(f);
                String safe = shortHex(f.getEntryPoint()) + "_" + sanitize(displayName(f));
                String path;
                String decStatus = "not-requested";

                if ("region".equalsIgnoreCase(t.mode)) {
                    File fnRegionDir = new File(regionDir, safe);
                    fnRegionDir.mkdirs();
                    int count = exportRegions(f, ins, fnRegionDir, regionIndex);
                    path = "v4_giant_regions/" + safe + "/ (" + count + " regions)";
                    decStatus = "region-mode";
                } else {
                    File asm = new File(asmDir, safe + ".asm");
                    writeFunctionAsm(f, ins, asm);
                    path = "v4_selected_ida/" + asm.getName();

                    if (!decompilerReady) {
                        decStatus = "decompiler-unavailable";
                    } else if (System.nanoTime() - started >= budgetNanos) {
                        decStatus = "budget-exhausted";
                    } else {
                        try {
                            DecompileResults r = decompiler.decompileFunction(f, timeoutSec, monitor);
                            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                                File c = new File(decompDir, safe + ".c");
                                try (PrintWriter w = writer(c)) {
                                    w.println("/* V4 selective pseudocode: reconstructed by Ghidra, not original source. */");
                                    w.println("/* entry=" + f.getEntryPoint() + " name=" + displayName(f) + " size=" + f.getBody().getNumAddresses() + " */");
                                    w.println(r.getDecompiledFunction().getC());
                                }
                                decStatus = "ok";
                            } else {
                                decStatus = "failed:" + clean(r == null ? "null" : r.getErrorMessage());
                            }
                        } catch (Exception e) {
                            decStatus = "exception:" + clean(e.toString());
                        }
                    }
                }

                index.println(csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + "," + csv(t.mode) + "," +
                    csv(t.score) + "," + f.getBody().getNumAddresses() + "," + ins.size() + "," + csv(decStatus) + "," + csv(path));
            }
        } finally {
            decompiler.dispose();
        }

        println("[v4] selective export complete");
    }

    private List<Target> readTargets(File file) throws Exception {
        List<Target> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String header = br.readLine();
            if (header == null) return out;
            List<String> hs = parseCsv(header);
            int entryI = hs.indexOf("entry");
            int nameI = hs.indexOf("name");
            int modeI = hs.indexOf("recommended_mode");
            int scoreI = hs.indexOf("score");
            if (entryI < 0 || modeI < 0) throw new IllegalArgumentException("selection CSV missing entry/recommended_mode");
            String line;
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                List<String> xs = parseCsv(line);
                Target t = new Target();
                t.entry = get(xs, entryI);
                t.name = get(xs, nameI);
                t.mode = get(xs, modeI);
                t.score = get(xs, scoreI);
                if (!t.entry.isEmpty()) out.add(t);
            }
        }
        return out;
    }

    private int exportRegions(Function f, List<Instruction> ins, File dir, PrintWriter regionIndex) throws Exception {
        if (ins.isEmpty()) return 0;
        List<Integer> centers = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        Set<Integer> occupied = new HashSet<>();

        addCenter(centers, reasons, occupied, 0, "entry", ins.size());
        for (int i = 0; i < ins.size(); i++) {
            Instruction x = ins.get(i);
            String m = x.getMnemonicString() == null ? "" : x.getMnemonicString().toUpperCase();
            if (x.getFlowType().isComputed() && x.getFlowType().isJump()) {
                addCenter(centers, reasons, occupied, i, "indirect-jump", ins.size());
            } else if (x.getFlowType().isComputed() && x.getFlowType().isCall()) {
                addCenter(centers, reasons, occupied, i, "indirect-call", ins.size());
            }

            int refs = incomingFlowRefs(x.getAddress());
            if (refs >= 12) addCenter(centers, reasons, occupied, i, "high-indegree:" + refs, ins.size());

            if ((m.equals("CMP") || m.equals("CMN") || m.equals("TST") || m.equals("CCMP") || m.equals("CCMN")) && i % 97 == 0) {
                addCenter(centers, reasons, occupied, i, "state-compare-sample", ins.size());
            }
            if (i > 0 && i % 900 == 0) addCenter(centers, reasons, occupied, i, "coverage-sample", ins.size());
            if (centers.size() >= 48) break;
        }

        int n = 0;
        for (int k = 0; k < centers.size(); k++) {
            int c = centers.get(k);
            int lo = Math.max(0, c - 36);
            int hi = Math.min(ins.size() - 1, c + 44);
            Instruction center = ins.get(c);
            String reason = reasons.get(k);
            String id = String.format("%02d", ++n);
            File out = new File(dir, "region_" + id + "_" + shortHex(center.getAddress()) + ".asm");
            try (PrintWriter w = writer(out)) {
                w.println("; V4 giant-function region");
                w.println("; function=" + displayName(f) + " entry=" + f.getEntryPoint() + " size=0x" + Long.toHexString(f.getBody().getNumAddresses()).toUpperCase());
                w.println("; center=" + center.getAddress() + " reason=" + reason);
                w.println("; window=" + ins.get(lo).getAddress() + ".." + ins.get(hi).getAddress());
                w.println("; callers: " + joinLimited(callers(f), 20));
                w.println();
                for (int i = lo; i <= hi; i++) writeInstruction(w, ins.get(i));
            }
            regionIndex.println(csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + "," + id + "," +
                csv(center.getAddress().toString()) + "," + csv(reason) + "," + csv(ins.get(lo).getAddress().toString()) + "," +
                csv(ins.get(hi).getAddress().toString()) + "," + (hi - lo + 1) + "," + csv("v4_giant_regions/" + dir.getName() + "/" + out.getName()));
        }
        return n;
    }

    private void addCenter(List<Integer> centers, List<String> reasons, Set<Integer> occupied, int idx, String reason, int size) {
        if (idx < 0 || idx >= size || centers.size() >= 48) return;
        int bucket = idx / 28;
        if (!occupied.add(bucket)) return;
        centers.add(idx);
        reasons.add(reason);
    }

    private int incomingFlowRefs(Address a) {
        int n = 0;
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(a);
        while (it.hasNext()) {
            Reference r = it.next();
            if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) n++;
        }
        return n;
    }

    private void writeFunctionAsm(Function f, List<Instruction> ins, File file) throws Exception {
        try (PrintWriter w = writer(file)) {
            w.println("; ============================================================================");
            w.println("; Mobile Ghidra Lab V4 - selective IDA-like listing");
            w.println("; FUNCTION " + displayName(f));
            w.println("; start=" + f.getEntryPoint() + " size=0x" + Long.toHexString(f.getBody().getNumAddresses()).toUpperCase());
            w.println("; callers: " + joinLimited(callers(f), 24));
            w.println("; callees: " + joinLimited(callees(f, ins), 24));
            w.println("; ============================================================================");
            for (Instruction x : ins) writeInstruction(w, x);
        }
    }

    private void writeInstruction(PrintWriter w, Instruction ins) {
        String bytes = bytes(ins);
        String m = ins.getMnemonicString() == null ? "" : ins.getMnemonicString().toUpperCase();
        String ops = operands(ins);
        String comment = "";
        if (ins.getFlowType().isComputed() && ins.getFlowType().isJump()) comment = " ; INDIRECT JUMP";
        else if (ins.getFlowType().isComputed() && ins.getFlowType().isCall()) comment = " ; INDIRECT CALL";
        w.printf(".text:%016X  %-13s %-9s %s%s%n", ins.getAddress().getOffset(), bytes, m, ops, comment);
    }

    private String operands(Instruction ins) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < ins.getNumOperands(); i++) {
            String s;
            try { s = ins.getDefaultOperandRepresentation(i); }
            catch (Exception e) { s = "?"; }
            out.add(s == null ? "" : s);
        }
        Address[] flows = ins.getFlows();
        if ((ins.getFlowType().isCall() || ins.getFlowType().isJump()) && flows != null && flows.length == 1 && !out.isEmpty()) {
            Address target = flows[0];
            if (target != null && target != Address.NO_ADDRESS) {
                Function cf = currentProgram.getFunctionManager().getFunctionAt(target);
                out.set(out.size() - 1, cf != null ? displayName(cf) : "loc_" + shortHex(target));
            }
        }
        return String.join(", ", out);
    }

    private List<Instruction> instructions(Function f) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && !monitor.isCancelled()) out.add(it.next());
        return out;
    }

    private List<String> callers(Function f) {
        Set<String> out = new LinkedHashSet<>();
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while (it.hasNext()) {
            Reference r = it.next();
            if (!r.getReferenceType().isCall()) continue;
            Function src = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (src != null) out.add(displayName(src) + "@" + r.getFromAddress());
        }
        return new ArrayList<>(out);
    }

    private List<String> callees(Function f, List<Instruction> ins) {
        Set<String> out = new LinkedHashSet<>();
        for (Instruction x : ins) {
            if (!x.getFlowType().isCall()) continue;
            Address[] flows = x.getFlows();
            if (flows == null || flows.length == 0) { out.add("<computed>"); continue; }
            for (Address a : flows) {
                Function cf = a == null ? null : currentProgram.getFunctionManager().getFunctionAt(a);
                out.add(cf == null ? (a == null ? "<unknown>" : "loc_" + shortHex(a)) : displayName(cf));
            }
        }
        return new ArrayList<>(out);
    }

    private Address parseTargetAddress(String s) {
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(s.trim(), 16));
        } catch (Exception e) {
            return null;
        }
    }

    private String displayName(Function f) {
        String n = f == null ? "" : f.getName();
        if (n == null || n.isEmpty() || n.startsWith("FUN_") || n.startsWith("LAB_") || n.startsWith("SUB_")) {
            return "sub_" + shortHex(f.getEntryPoint());
        }
        return n;
    }

    private String bytes(Instruction ins) {
        try {
            byte[] bs = ins.getBytes();
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < bs.length; i++) {
                if (i > 0) b.append(' ');
                b.append(String.format("%02X", bs[i] & 0xff));
            }
            return b.toString();
        } catch (Exception e) { return "??"; }
    }

    private String shortHex(Address a) { return Long.toHexString(a.getOffset()).toUpperCase(); }
    private String sanitize(String s) {
        String x = (s == null ? "function" : s).replaceAll("[^A-Za-z0-9._-]+", "_");
        return x.length() > 96 ? x.substring(0, 96) : x;
    }
    private String joinLimited(List<String> xs, int max) {
        if (xs == null || xs.isEmpty()) return "-";
        if (xs.size() <= max) return String.join(", ", xs);
        return String.join(", ", xs.subList(0, max)) + ", ... +" + (xs.size() - max);
    }
    private PrintWriter writer(File f) throws Exception {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8));
    }
    private int parseInt(String s, int fallback) { try { return Integer.parseInt(s); } catch (Exception e) { return fallback; } }
    private String clean(String s) { return s == null ? "" : s.replace('\r', ' ').replace('\n', ' '); }
    private String csv(String s) {
        if (s == null) s = "";
        return "\"" + s.replace("\"", "\"\"").replace("\r", " ").replace("\n", " ") + "\"";
    }
    private String get(List<String> xs, int i) { return i >= 0 && i < xs.size() ? xs.get(i) : ""; }

    private List<String> parseCsv(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') { cur.append('"'); i++; }
                    else quoted = false;
                } else cur.append(c);
            } else {
                if (c == '"') quoted = true;
                else if (c == ',') { out.add(cur.toString()); cur.setLength(0); }
                else cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }
}
