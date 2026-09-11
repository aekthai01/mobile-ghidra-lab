// IDA-like ARM64 listing exporter for headless Ghidra.
// @category MobileGhidraLab

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.MemoryBlock;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.StackReference;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportIdaListing extends GhidraScript {

    private File outDir;
    private File perFunctionDir;
    private final Map<Address, String> labels = new HashMap<>();
    private final Set<Address> branchTargets = new HashSet<>();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("ExportIdaListing.java requires output directory argument");
        }

        outDir = new File(args[0]);
        perFunctionDir = new File(outDir, "ida_like_functions");
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IllegalStateException("Could not create output directory: " + outDir);
        }
        if (!perFunctionDir.exists() && !perFunctionDir.mkdirs()) {
            throw new IllegalStateException("Could not create per-function output directory: " + perFunctionDir);
        }

        collectLabels();
        exportAddressMap();
        exportCallIndex();
        exportFullListing();
        exportPerFunctionListings();
        exportReadme();

        println("[mobile-ghidra-lab] IDA-like listing exported");
    }

    private void collectLabels() {
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            labels.put(f.getEntryPoint(), functionName(f));
        }

        InstructionIterator iit = currentProgram.getListing().getInstructions(true);
        while (iit.hasNext() && !monitor.isCancelled()) {
            Instruction ins = iit.next();
            Address[] flows = ins.getFlows();
            if (flows == null) continue;
            for (Address target : flows) {
                if (target == null || target == Address.NO_ADDRESS) continue;
                if (!currentProgram.getMemory().contains(target)) continue;
                if (ins.getFlowType().isJump()) {
                    branchTargets.add(target);
                    if (!labels.containsKey(target)) {
                        labels.put(target, "loc_" + shortHex(target));
                    }
                }
                else if (ins.getFlowType().isCall()) {
                    Function callee = currentProgram.getFunctionManager().getFunctionAt(target);
                    if (callee != null) {
                        labels.put(target, functionName(callee));
                    }
                }
            }
        }
    }

    private void exportAddressMap() throws Exception {
        List<Address> addrs = new ArrayList<>(labels.keySet());
        Collections.sort(addrs);
        try (PrintWriter w = writer("ida_address_map.csv")) {
            w.println("address,label,type,function");
            for (Address a : addrs) {
                Function exact = currentProgram.getFunctionManager().getFunctionAt(a);
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(a);
                String type = exact != null ? "function" : (branchTargets.contains(a) ? "code_label" : "label");
                w.println(csv(a.toString()) + "," + csv(labels.get(a)) + "," + csv(type) + "," +
                    csv(owner == null ? "" : functionName(owner)));
            }
        }
    }

    private void exportCallIndex() throws Exception {
        try (PrintWriter w = writer("ida_call_xrefs.csv")) {
            w.println("caller_entry,caller_name,callsite,callee_entry,callee_name,kind");
            InstructionIterator iit = currentProgram.getListing().getInstructions(true);
            while (iit.hasNext() && !monitor.isCancelled()) {
                Instruction ins = iit.next();
                if (!ins.getFlowType().isCall()) continue;
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
                Address[] flows = ins.getFlows();
                if (flows == null || flows.length == 0) {
                    w.println(csv(caller == null ? "" : caller.getEntryPoint().toString()) + "," +
                        csv(caller == null ? "" : functionName(caller)) + "," + csv(ins.getAddress().toString()) +
                        ",,,computed");
                    continue;
                }
                for (Address target : flows) {
                    Function callee = target == null ? null : currentProgram.getFunctionManager().getFunctionAt(target);
                    w.println(csv(caller == null ? "" : caller.getEntryPoint().toString()) + "," +
                        csv(caller == null ? "" : functionName(caller)) + "," + csv(ins.getAddress().toString()) + "," +
                        csv(target == null ? "" : target.toString()) + "," +
                        csv(callee == null ? targetLabel(target) : functionName(callee)) + "," +
                        csv(ins.getFlowType().isComputed() ? "computed" : "direct"));
                }
            }
        }
    }

    private void exportFullListing() throws Exception {
        try (PrintWriter w = writer("ida_like_full.asm")) {
            writeBanner(w);
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext() && !monitor.isCancelled()) {
                Function f = fit.next();
                writeFunction(w, f);
                w.println();
            }
        }
    }

    private void exportPerFunctionListings() throws Exception {
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            String safe = sanitize(functionName(f));
            File file = new File(perFunctionDir, shortHex(f.getEntryPoint()) + "_" + safe + ".asm");
            try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
                writeBanner(w);
                writeFunction(w, f);
            }
        }
    }

    private void writeBanner(PrintWriter w) {
        w.println("; ============================================================================");
        w.println("; Mobile Ghidra Lab - IDA-like listing");
        w.println("; Program: " + currentProgram.getName());
        w.println("; Language: " + currentProgram.getLanguageID());
        w.println("; This is reconstructed by Ghidra, not an IDA database and not original source.");
        w.println("; ============================================================================");
        w.println();
    }

    private void writeFunction(PrintWriter w, Function f) {
        String fn = functionName(f);
        String section = sectionName(f.getEntryPoint());
        List<String> callers = functionCallers(f);
        List<String> callees = functionCallees(f);

        w.println("; ---------------------------------------------------------------------------");
        w.println("; FUNCTION " + fn);
        w.println("; start=" + f.getEntryPoint() + "  size=0x" + Long.toHexString(f.getBody().getNumAddresses()).toUpperCase());
        try {
            w.println("; signature: " + f.getSignature());
        } catch (Exception ignored) {
        }
        w.println("; callers(" + callers.size() + "): " + joinLimited(callers, 24));
        w.println("; callees(" + callees.size() + "): " + joinLimited(callees, 24));
        writeStackFrameSummary(w, f);
        w.println(section + ":" + fullHex(f.getEntryPoint()) + "             " + fn);

        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            Address addr = ins.getAddress();

            if (!addr.equals(f.getEntryPoint()) && labels.containsKey(addr)) {
                w.println();
                String xrefs = codeXrefs(addr);
                w.printf("%-39s %-40s%s%n",
                    sectionName(addr) + ":" + fullHex(addr), labels.get(addr),
                    xrefs.isEmpty() ? "" : " ; CODE XREF: " + xrefs);
            }

            String bytes = instructionBytes(ins);
            String mnemonic = ins.getMnemonicString() == null ? "" : ins.getMnemonicString().toUpperCase();
            String operands = formattedOperands(ins);
            String comment = instructionComment(ins, f);

            w.printf("%-22s %-13s %-15s %-10s %s%s%n",
                sectionName(addr) + ":" + fullHex(addr), bytes, "", mnemonic, operands,
                comment.isEmpty() ? "" : " ; " + comment);
        }
    }

    private void writeStackFrameSummary(PrintWriter w, Function f) {
        try {
            StackFrame sf = f.getStackFrame();
            Variable[] vars = sf.getStackVariables();
            w.println("; frame_size=0x" + Integer.toHexString(sf.getFrameSize()).toUpperCase() +
                " locals=0x" + Integer.toHexString(sf.getLocalSize()).toUpperCase() +
                " params=0x" + Integer.toHexString(sf.getParameterSize()).toUpperCase());
            if (vars != null && vars.length > 0) {
                List<String> parts = new ArrayList<>();
                for (Variable v : vars) {
                    if (parts.size() >= 20) break;
                    parts.add(stackVariableName(v.getStackOffset(), v) + "=" + signedHex(v.getStackOffset()));
                }
                w.println("; stack_vars: " + String.join(", ", parts));
            }
        } catch (Exception ignored) {
        }
    }

    private List<String> functionCallers(Function f) {
        Set<String> out = new LinkedHashSet<>();
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while (it.hasNext()) {
            Reference r = it.next();
            if (!r.getReferenceType().isCall()) continue;
            Function src = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (src == null) continue;
            long delta = r.getFromAddress().getOffset() - src.getEntryPoint().getOffset();
            out.add(functionName(src) + "+" + Long.toHexString(delta).toUpperCase());
        }
        return new ArrayList<>(out);
    }

    private List<String> functionCallees(Function f) {
        Set<String> out = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall()) continue;
            Address[] flows = ins.getFlows();
            if (flows == null || flows.length == 0) {
                out.add("<computed>");
                continue;
            }
            for (Address target : flows) {
                if (target == null || target == Address.NO_ADDRESS) continue;
                Function callee = currentProgram.getFunctionManager().getFunctionAt(target);
                out.add(callee == null ? targetLabel(target) : functionName(callee));
            }
        }
        return new ArrayList<>(out);
    }

    private String formattedOperands(Instruction ins) {
        int n = ins.getNumOperands();
        if (n <= 0) return "";

        List<String> ops = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String s;
            try {
                s = ins.getDefaultOperandRepresentation(i);
            } catch (Exception e) {
                s = "?";
            }
            ops.add(s == null ? "" : s);
        }

        Address[] flows = ins.getFlows();
        if ((ins.getFlowType().isJump() || ins.getFlowType().isCall()) && flows != null && flows.length == 1 && n > 0) {
            Address target = flows[0];
            if (target != null && target != Address.NO_ADDRESS) {
                ops.set(n - 1, targetLabel(target));
            }
        }

        return String.join(", ", ops);
    }

    private String instructionComment(Instruction ins, Function owner) {
        List<String> notes = new ArrayList<>();

        Reference[] refs = ins.getReferencesFrom();
        if (refs != null) {
            for (Reference r : refs) {
                if (r == null) continue;
                if (r.isStackReference()) {
                    try {
                        int off = ((StackReference) r).getStackOffset();
                        Variable v = owner.getStackFrame().getVariableContaining(off);
                        notes.add("STACK " + stackVariableName(off, v) + "=" + signedHex(off));
                    } catch (Exception ignored) {
                    }
                }
                else if (!r.getReferenceType().isFlow() && r.isMemoryReference()) {
                    Address to = r.getToAddress();
                    if (to != null && currentProgram.getMemory().contains(to)) {
                        notes.add("DATA -> " + dataLabel(to));
                    }
                }
            }
        }

        if (ins.getFlowType().isCall() && ins.getFlowType().isComputed()) {
            notes.add("INDIRECT CALL");
        }
        else if (ins.getFlowType().isJump() && ins.getFlowType().isComputed()) {
            notes.add("INDIRECT JUMP");
        }

        if (notes.size() > 4) {
            return String.join(" | ", notes.subList(0, 4)) + " | ...";
        }
        return String.join(" | ", notes);
    }

    private String codeXrefs(Address target) {
        List<String> xs = new ArrayList<>();
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(target);
        while (it.hasNext()) {
            Reference r = it.next();
            if (!r.getReferenceType().isFlow() || r.getReferenceType().isFallthrough()) continue;
            Function src = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            String base = src == null ? "loc_" + shortHex(r.getFromAddress()) : functionName(src);
            String plus = "";
            if (src != null) {
                long d = r.getFromAddress().getOffset() - src.getEntryPoint().getOffset();
                if (d != 0) plus = "+" + Long.toHexString(d).toUpperCase();
            }
            String arrow = r.getFromAddress().compareTo(target) < 0 ? "↓" : "↑";
            String kind = r.getReferenceType().isCall() ? "p" : "j";
            xs.add(base + plus + arrow + kind);
            if (xs.size() >= 8) break;
        }
        return String.join(", ", xs);
    }

    private String functionName(Function f) {
        if (f == null) return "";
        String n = f.getName();
        if (n == null || n.isEmpty() || n.startsWith("FUN_") || n.startsWith("LAB_")) {
            return "sub_" + shortHex(f.getEntryPoint());
        }
        return n;
    }

    private String targetLabel(Address a) {
        if (a == null || a == Address.NO_ADDRESS) return "<unknown>";
        String s = labels.get(a);
        if (s != null) return s;
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null) return functionName(f);
        if (currentProgram.getMemory().contains(a)) return "loc_" + shortHex(a);
        return "0x" + Long.toHexString(a.getOffset()).toUpperCase();
    }

    private String dataLabel(Address a) {
        try {
            ghidra.program.model.listing.Data d = currentProgram.getListing().getDataAt(a);
            if (d != null) {
                int len = d.getLength();
                String pfx = len == 1 ? "byte_" : len == 2 ? "word_" : len == 4 ? "dword_" : len == 8 ? "qword_" : len == 16 ? "xmmword_" : "data_";
                return pfx + shortHex(a);
            }
        } catch (Exception ignored) {
        }
        return "data_" + shortHex(a);
    }

    private String stackVariableName(int offset, Variable v) {
        if (v != null) {
            String n = v.getName();
            if (n != null && !n.isEmpty() && !n.startsWith("local_")) return n;
        }
        if (offset < 0) return "var_" + Integer.toHexString(-offset).toUpperCase();
        return "arg_" + Integer.toHexString(offset).toUpperCase();
    }

    private String instructionBytes(Instruction ins) {
        try {
            byte[] bs = ins.getBytes();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bs.length; i++) {
                if (i > 0) sb.append(' ');
                sb.append(String.format("%02X", bs[i] & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "??";
        }
    }

    private String sectionName(Address a) {
        try {
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            if (b != null && b.getName() != null && !b.getName().isEmpty()) {
                String n = b.getName();
                return n.startsWith(".") ? n : "." + n;
            }
        } catch (Exception ignored) {
        }
        return ".text";
    }

    private String fullHex(Address a) {
        return String.format("%016X", a.getOffset());
    }

    private String shortHex(Address a) {
        return Long.toHexString(a.getOffset()).toUpperCase();
    }

    private String signedHex(int n) {
        if (n < 0) return "-0x" + Integer.toHexString(-n).toUpperCase();
        return "+0x" + Integer.toHexString(n).toUpperCase();
    }

    private String joinLimited(List<String> xs, int max) {
        if (xs == null || xs.isEmpty()) return "-";
        if (xs.size() <= max) return String.join(", ", xs);
        return String.join(", ", xs.subList(0, max)) + ", ... +" + (xs.size() - max) + " more";
    }

    private String sanitize(String s) {
        if (s == null || s.isEmpty()) return "function";
        String x = s.replaceAll("[^A-Za-z0-9._-]+", "_");
        if (x.length() > 100) x = x.substring(0, 100);
        return x.isEmpty() ? "function" : x;
    }

    private PrintWriter writer(String name) throws Exception {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(outDir, name)), StandardCharsets.UTF_8));
    }

    private String csv(String s) {
        if (s == null) s = "";
        return "\"" + s.replace("\"", "\"\"").replace("\r", " ").replace("\n", " ") + "\"";
    }

    private void exportReadme() throws Exception {
        try (PrintWriter w = writer("IDA_LIKE_README.md")) {
            w.println("# IDA-like ARM64 listing");
            w.println();
            w.println("- `ida_like_full.asm`: all recovered functions in an IDA-inspired text layout.");
            w.println("- `ida_like_functions/`: one `.asm` file per recovered function for easier reading on mobile/AI tools.");
            w.println("- `ida_call_xrefs.csv`: direct/computed call index.");
            w.println("- `ida_address_map.csv`: recovered function and branch labels.");
            w.println();
            w.println("The exporter adds raw instruction bytes, `sub_`/`loc_` labels, CODE XREF comments, caller/callee summaries, stack-variable hints, data-reference hints, and symbolic direct branch/call targets.");
            w.println();
            w.println("It cannot reproduce IDA-specific database metadata exactly. In particular, IDA's exact stack-frame names and manually curated types/comments are not present unless Ghidra independently recovered equivalent information.");
        }
    }
}
