// Fair-budget raw P-code exporter for Mobile Ghidra Lab V5.1.
// @category MobileGhidraLab

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportV51RawPcode extends GhidraScript {
    private static class Target { String entry, name, mode, tier; int rank; }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("ExportV51RawPcode.java <outDir> <selectionCsv> [maxFunctions] [maxInstructionsPerFunction] [maxOpsPerFunction] [maxOpsTotal]");
        File outDir = new File(args[0]);
        File selection = new File(args[1]);
        int maxFunctions = args.length >= 3 ? parseInt(args[2], 180) : 180;
        int maxInstructionsPerFunction = args.length >= 4 ? parseInt(args[3], 6000) : 6000;
        int maxOpsPerFunction = args.length >= 5 ? parseInt(args[4], 18000) : 18000;
        int maxOpsTotal = args.length >= 6 ? parseInt(args[5], 1000000) : 1000000;
        outDir.mkdirs();

        List<Target> targets = readTargets(selection, maxFunctions);
        int totalOps = 0, totalInstructions = 0, exportedFunctions = 0;
        try (PrintWriter out = writer(new File(outDir, "v51_raw_pcode.csv"));
             PrintWriter summary = writer(new File(outDir, "v51_raw_pcode_summary.csv"))) {
            out.println("rank,function_entry,function_name,mode,tier,instruction_address,pcode_index,opcode,mnemonic,output,inputs");
            summary.println("rank,function_entry,function_name,mode,tier,instructions,pcode_ops,truncated,truncate_reason");
            for (Target t : targets) {
                if (monitor.isCancelled() || totalOps >= maxOpsTotal) break;
                Address a = parseEntryAddress(t.entry);
                Function f = a == null ? null : currentProgram.getFunctionManager().getFunctionAt(a);
                if (f == null && a != null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
                if (f == null) continue;
                int functionOps = 0, functionInstructions = 0;
                boolean truncated = false; String reason = "";
                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (it.hasNext() && !monitor.isCancelled()) {
                    if (functionInstructions >= maxInstructionsPerFunction) { truncated=true; reason="instruction_cap"; break; }
                    if (functionOps >= maxOpsPerFunction) { truncated=true; reason="per_function_op_cap"; break; }
                    if (totalOps >= maxOpsTotal) { truncated=true; reason="global_op_cap"; break; }
                    Instruction ins = it.next();
                    functionInstructions++; totalInstructions++;
                    PcodeOp[] ops = ins.getPcode();
                    if (ops == null) continue;
                    for (int i=0; i<ops.length; i++) {
                        if (functionOps >= maxOpsPerFunction) { truncated=true; reason="per_function_op_cap"; break; }
                        if (totalOps >= maxOpsTotal) { truncated=true; reason="global_op_cap"; break; }
                        PcodeOp op = ops[i];
                        StringBuilder inputs = new StringBuilder();
                        for (int k=0; k<op.getNumInputs(); k++) {
                            if (k>0) inputs.append(" | ");
                            inputs.append(varnode(op.getInput(k)));
                        }
                        out.println(t.rank + "," + csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + "," + csv(t.mode) + "," + csv(t.tier) + "," +
                            csv(ins.getAddress().toString()) + "," + i + "," + op.getOpcode() + "," + csv(op.getMnemonic()) + "," + csv(varnode(op.getOutput())) + "," + csv(inputs.toString()));
                        functionOps++; totalOps++;
                    }
                    if (truncated) break;
                }
                exportedFunctions++;
                summary.println(t.rank + "," + csv(f.getEntryPoint().toString()) + "," + csv(displayName(f)) + "," + csv(t.mode) + "," + csv(t.tier) + "," + functionInstructions + "," + functionOps + "," + truncated + "," + csv(reason));
            }
        }
        try (PrintWriter w = writer(new File(outDir, "v51_raw_pcode_report.md"))) {
            w.println("# V5.1 fair-budget raw P-code export\n");
            w.println("Each function has its own instruction/P-code cap so giant functions cannot consume the entire export budget before JNI/app execution paths are reached.\n");
            w.println("- Functions requested: **" + targets.size() + "**");
            w.println("- Functions exported: **" + exportedFunctions + "**");
            w.println("- Instructions visited: **" + totalInstructions + "**");
            w.println("- P-code operations exported: **" + totalOps + "**");
            w.println("- Per-function op cap: **" + maxOpsPerFunction + "**");
            w.println("- Global op cap: **" + maxOpsTotal + "**");
        }
        println("[v5.1] fair raw p-code functions=" + exportedFunctions + " ops=" + totalOps);
    }

    private List<Target> readTargets(File file, int max) throws Exception {
        List<Target> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String header = br.readLine(); if (header == null) return out;
            List<String> hs = parseCsv(header);
            int entryI=hs.indexOf("entry"), nameI=hs.indexOf("name"), modeI=hs.indexOf("recommended_mode"), tierI=hs.indexOf("v51_priority_tier");
            String line; int rank=0;
            while ((line=br.readLine()) != null && out.size()<max) {
                if (line.trim().isEmpty()) continue;
                List<String> xs=parseCsv(line); Target t=new Target();
                t.entry=get(xs,entryI); t.name=get(xs,nameI); t.mode=get(xs,modeI); t.tier=get(xs,tierI); t.rank=++rank;
                if (!t.entry.isEmpty()) out.add(t);
            }
        }
        return out;
    }

    private Address parseEntryAddress(String s) { try { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(s.trim(),16)); } catch(Exception e){ return null; } }
    private String displayName(Function f) { String n=f==null?"":f.getName(); if(n==null||n.isEmpty()||n.startsWith("FUN_")||n.startsWith("LAB_")||n.startsWith("SUB_")) return "sub_"+Long.toHexString(f.getEntryPoint().getOffset()).toUpperCase(); return n; }
    private String varnode(Varnode v) { return v==null?"":v.toString(); }
    private int parseInt(String s,int fallback){ try{return Integer.parseInt(s);}catch(Exception e){return fallback;} }
    private PrintWriter writer(File f)throws Exception{return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8)),true);}
    private String csv(String s){if(s==null)return "\"\"";return "\""+s.replace("\"","\"\"").replace("\r"," ").replace("\n","\\n")+"\"";}
    private String get(List<String> xs,int i){return i>=0&&i<xs.size()?xs.get(i):"";}
    private List<String> parseCsv(String line){List<String> out=new ArrayList<>();StringBuilder cur=new StringBuilder();boolean q=false;for(int i=0;i<line.length();i++){char c=line.charAt(i);if(c=='\"'){if(q&&i+1<line.length()&&line.charAt(i+1)=='\"'){cur.append('\"');i++;}else q=!q;}else if(c==','&&!q){out.add(cur.toString());cur.setLength(0);}else cur.append(c);}out.add(cur.toString());return out;}
}
