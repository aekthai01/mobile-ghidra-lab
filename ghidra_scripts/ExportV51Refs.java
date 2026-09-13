// Function-reference exporter for Mobile Ghidra Lab V5.1.
// @category MobileGhidraLab

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class ExportV51Refs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("ExportV51Refs.java <outDir>");
        File outDir = new File(args[0]);
        outDir.mkdirs();
        ReferenceManager rm = currentProgram.getReferenceManager();
        int count = 0;
        try (PrintWriter out = writer(new File(outDir, "v51_function_refs.csv"))) {
            out.println("target_function_entry,target_function_name,from_address,from_function_entry,from_function_name,reference_type,is_call,is_flow,is_data,source_type");
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext() && !monitor.isCancelled()) {
                Function target = fit.next();
                Address entry = target.getEntryPoint();
                ReferenceIterator it = rm.getReferencesTo(entry);
                while (it.hasNext() && !monitor.isCancelled()) {
                    Reference ref = it.next();
                    Address from = ref.getFromAddress();
                    Function owner = currentProgram.getFunctionManager().getFunctionContaining(from);
                    String type = ref.getReferenceType().toString();
                    out.println(csv(entry.toString()) + "," + csv(displayName(target)) + "," + csv(from.toString()) + "," +
                        csv(owner == null ? "" : owner.getEntryPoint().toString()) + "," + csv(owner == null ? "" : displayName(owner)) + "," +
                        csv(type) + "," + ref.getReferenceType().isCall() + "," + ref.getReferenceType().isFlow() + "," +
                        ref.getReferenceType().isData() + "," + csv(ref.getSource().toString()));
                    count++;
                }
            }
        }
        println("[v5.1] function refs exported=" + count);
    }

    private String displayName(Function f) {
        String n = f == null ? "" : f.getName();
        if (n == null || n.isEmpty() || n.startsWith("FUN_") || n.startsWith("LAB_") || n.startsWith("SUB_")) {
            return "sub_" + Long.toHexString(f.getEntryPoint().getOffset()).toUpperCase();
        }
        return n;
    }

    private PrintWriter writer(File file) throws Exception {
        return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)), true);
    }

    private String csv(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\"", "\"\"").replace("\r", " ").replace("\n", "\\n") + "\"";
    }
}
