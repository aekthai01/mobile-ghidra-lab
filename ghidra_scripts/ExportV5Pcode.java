// Raw P-code exporter for Mobile Ghidra Lab V5.
// @category MobileGhidraLab

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ExportV5Pcode extends GhidraScript {
    private static class Target {
        String entry;
        String name;
        String mode;
        int rank;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("ExportV5Pcode.java <outDir> <selectionCsv> [maxFunctions] [maxInstructionsPerFunction] [maxOpsTotal]");
        }
        File outDir = new File(args[0]);
        File selection = new File(args[1]);
        int maxFunctions = args.length >= 3 ? parseInt(args[2], 120) : 120;
        int maxInstructionsPerFunction = args.length >= 4 ? parseInt(args[3], 12000) : 12000;
        int maxOpsTotal = args.length >= 5 ? parseInt(args[4], 600000) : 600000;
        outDir.mkdirs();

        List<Target> targets = readTargets(selection, maxFunctions);
        int totalOps = 0;
        int totalInstructions = 0;
        int exportedFunctions = 0;

        try (PrintWriter out = writer(new File(outDir, "v5_pcode.csv"));
             PrintWriter summary = writer(new File(outDir, "v5_pcode_summary.csv"))) {
            out.println("rank,function_entry,function_name,mode,instruction_address,pcode_index,opcode,mnemonic,output,inputs");
            summary.println("rank,function_entry,function_name,mode,instructions,pcode_ops,truncated");

            for (Target t : targets) {
                if (monitor.isCancelled() || totalOps >= maxOpsTotal) break;
                Address a = parseAddress(t.entry);
                Function f = a == null ? null : currentProgram.getFunctionManager().getFunctionAt(a);
                if (f == null && a != null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
                if (f == null) continue;

                int functionOps = 0;
                int functionInstructions = 0;
                boolean truncated = false;
                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (it.hasNext() && !monitor.isCancelled()) {
                    Instruction ins = it.next();
                    functionInstructions++;
                    totalInstructions++;
                    if (functionInstructions > maxInstructionsPerFunction || totalOps >= maxOpsTotal) {
                        truncated = true;
                        break;
                    }
                    PcodeOp[] ops = ins.getPcode();
                    if (ops == null) continue;
                    for (int i = 0; i < ops.length; i++) {
                        if (totalOps >= maxOpsTotal) {
                            truncated = true;
                            break;
                        }
                        PcodeOp op = ops[i];
                        StringBuilder inputs = new StringBuilder();
                        for (int k = 0; k < op.getNumInputs(); k++) {
                            if (k > 0) inputs.append(" | ");
                            inputs.append(varnode(op.getInput(k)));
                        }
                        out.println(t.rank + "," + csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + "," + csv(t.mode) + "," +
                            csv(ins.getAddress().toString()) + "," + i + "," + op.getOpcode() + "," + csv(op.getMnemonic()) + "," +
                            csv(varnode(op.getOutput())) + "," + csv(inputs.toString()));
                        functionOps++;
                        totalOps++;
                    }
                }
                exportedFunctions++;
                summary.println(t.rank + "," + csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + "," + csv(t.mode) + "," +
                    functionInstructions + "," + functionOps + "," + truncated);
            }
        }

        try (PrintWriter w = writer(new File(outDir, "v5_pcode_report.md"))) {
            w.println("# V5 raw P-code export\n");
            w.println("Raw instruction P-code is an architecture-normalized intermediate representation from Ghidra. It is not SSA/high P-code and it is not original source.\n");
            w.println("- Selected functions requested: **" + targets.size() + "**");
            w.println("- Functions exported: **" + exportedFunctions + "**");
            w.println("- Instructions visited: **" + totalInstructions + "**");
            w.println("- P-code operations exported: **" + totalOps + "**");
            w.println("- Max functions: **" + maxFunctions + "**");
            w.println("- Max instructions/function: **" + maxInstructionsPerFunction + "**");
            w.println("- Max total P-code ops: **" + maxOpsTotal + "**");
            w.println("\nUse this evidence to correlate register/value flow across ARM64 instruction sequences. The V5 flow resolver keeps conservative claims separate from inferred edges.");
        }
        println("[v5] raw p-code export complete: functions=" + exportedFunctions + " ops=" + totalOps);
    }

    private List<Target> readTargets(File file, int max) throws Exception {
        List<Target> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String header = br.readLine();
            if (header == null) return out;
            List<String> hs = parseCsv(header);
            int entryI = hs.indexOf("entry");
            int nameI = hs.indexOf("name");
            int modeI = hs.indexOf("recommended_mode");
            String line;
            int rank = 0;
            while ((line = br.readLine()) != null && out.size() < max) {
                if (line.trim().isEmpty()) continue;
                List<String> xs = parseCsv(line);
                Target t = new Target();
                t.entry = get(xs, entryI);
                t.name = get(xs, nameI);
                t.mode = get(xs, modeI);
                t.rank = ++rank;
                if (!t.entry.isEmpty()) out.add(t);
            }
        }
        return out;
    }

    private Address parseAddress(String s) {
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(s.trim(), 16));
        } catch (Exception e) {
            return null;
        }
    }

    private String displayName(Function f) {
        String n = f == null ? "" : f.getName();
        if (n == null || n.isEmpty() || n.startsWith("FUN_") || n.startsWith("LAB_") || n.startsWith("SUB_")) {
            return "sub_" + Long.toHexString(f.getEntryPoint().getOffset()).toUpperCase();
        }
        return n;
    }

    private String varnode(Varnode v) {
        return v == null ? "" : v.toString();
    }

    private int parseInt(String s, int fallback) {
        try { return Integer.parseInt(s); } catch (Exception e) { return fallback; }
    }

    private PrintWriter writer(File file) throws Exception {
        return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)), true);
    }

    private String csv(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\"", "\"\"").replace("\r", " ").replace("\n", "\\n") + "\"";
    }

    private String get(List<String> xs, int i) {
        return i >= 0 && i < xs.size() ? xs.get(i) : "";
    }

    private List<String> parseCsv(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    cur.append('"');
                    i++;
                } else quoted = !quoted;
            } else if (c == ',' && !quoted) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }
}
