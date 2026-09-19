// Login/network seed exporter for Mobile Ghidra Lab V5.6.
// @category MobileGhidraLab

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.model.data.StringDataInstance;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportV56LoginSeeds extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("ExportV56LoginSeeds.java <outDir>");
        File outDir = new File(args[0]);
        outDir.mkdirs();
        File outFile = new File(outDir, "v56_login_seeds.csv");
        Set<String> dedupe = new LinkedHashSet<>();
        int immCount = 0, httpsCount = 0;

        try (PrintWriter out = writer(outFile)) {
            out.println("function_entry,function_name,kind,evidence_address,value,detail");

            InstructionIterator it = currentProgram.getListing().getInstructions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Instruction ins = it.next();
                boolean hit = false;
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    try {
                        Scalar s = ins.getScalar(i);
                        if (s != null && s.getUnsignedValue() == 0x2712L) {
                            hit = true;
                            break;
                        }
                    } catch (Exception ignored) {}
                }
                if (!hit) continue;
                Function f = currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
                if (f == null) continue;
                String key = f.getEntryPoint() + "|imm_0x2712|" + ins.getAddress();
                if (dedupe.add(key)) {
                    out.println(csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + ",imm_0x2712," +
                        csv(ins.getAddress().toString()) + "," + csv("0x2712") + "," + csv(ins.toString()));
                    immCount++;
                }
            }

            DefinedDataIterator dit = DefinedDataIterator.byDataInstance(currentProgram, data -> StringDataInstance.isString(data));
            while (dit.hasNext() && !monitor.isCancelled()) {
                Data d = dit.next();
                String value = d.getDefaultValueRepresentation();
                if (value == null || !value.toLowerCase(Locale.ROOT).contains("https")) continue;
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                while (refs.hasNext() && !monitor.isCancelled()) {
                    Reference ref = refs.next();
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (f == null) continue;
                    String key = f.getEntryPoint() + "|https_xref|" + ref.getFromAddress() + "|" + d.getAddress();
                    if (dedupe.add(key)) {
                        out.println(csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + ",https_xref," +
                            csv(ref.getFromAddress().toString()) + "," + csv(value) + "," + csv("string@" + d.getAddress()));
                        httpsCount++;
                    }
                }
            }
        }
        println("[v5.6] login seeds imm_0x2712=" + immCount + " https_xrefs=" + httpsCount);
    }

    private String displayName(Function f) {
        String n = f == null ? "" : f.getName();
        if (n == null || n.isEmpty() || n.startsWith("FUN_") || n.startsWith("LAB_") || n.startsWith("SUB_"))
            return "sub_" + Long.toHexString(f.getEntryPoint().getOffset()).toUpperCase();
        return n;
    }

    private PrintWriter writer(File f) throws Exception {
        return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8)), true);
    }
    private String csv(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\"", "\"\"").replace("\r", " ").replace("\n", "\\n") + "\"";
    }
}
