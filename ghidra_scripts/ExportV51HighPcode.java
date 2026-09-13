// SSA/high P-code exporter for Mobile Ghidra Lab V5.1.
// @category MobileGhidraLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportV51HighPcode extends GhidraScript {
    private static class Target { String entry, name, mode, tier; int rank, size; }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("ExportV51HighPcode.java <outDir> <selectionCsv> [maxFunctions] [timeoutSec] [maxOpsPerFunction] [maxOpsTotal]");
        File outDir = new File(args[0]);
        File selection = new File(args[1]);
        int maxFunctions = args.length >= 3 ? parseInt(args[2], 80) : 80;
        int timeoutSec = args.length >= 4 ? parseInt(args[3], 8) : 8;
        int maxOpsPerFunction = args.length >= 5 ? parseInt(args[4], 30000) : 30000;
        int maxOpsTotal = args.length >= 6 ? parseInt(args[5], 600000) : 600000;
        outDir.mkdirs();

        List<Target> targets = readTargets(selection, maxFunctions);
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        decomp.setOptions(opts);
        decomp.toggleCCode(false);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        if (!decomp.openProgram(currentProgram)) throw new IllegalStateException("Decompiler could not open program");

        int totalOps=0, exported=0, failed=0;
        try (PrintWriter out=writer(new File(outDir,"v51_high_pcode.csv"));
             PrintWriter summary=writer(new File(outDir,"v51_high_pcode_summary.csv"))) {
            out.println("rank,function_entry,function_name,mode,tier,sequence_address,sequence_time,opcode,mnemonic,output,inputs");
            summary.println("rank,function_entry,function_name,mode,tier,size_bytes,status,high_pcode_ops,truncated");
            for (Target t: targets) {
                if (monitor.isCancelled() || totalOps >= maxOpsTotal) break;
                // Region-mode giants are handled by bounded raw P-code and ARM64 semantic slices.
                if ("region".equalsIgnoreCase(t.mode) && t.size >= 12000) {
                    summary.println(t.rank+","+csv(t.entry)+","+csv(t.name)+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("skipped:giant_region")+",0,false");
                    continue;
                }
                Address a=parseEntryAddress(t.entry);
                Function f=a==null?null:currentProgram.getFunctionManager().getFunctionAt(a);
                if(f==null&&a!=null) f=currentProgram.getFunctionManager().getFunctionContaining(a);
                if(f==null){failed++; summary.println(t.rank+","+csv(t.entry)+","+csv(t.name)+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("missing_function")+",0,false"); continue;}
                DecompileResults res=decomp.decompileFunction(f,timeoutSec,monitor);
                HighFunction high=res==null?null:res.getHighFunction();
                if(high==null){failed++; String msg=res==null?"no_result":res.getErrorMessage(); summary.println(t.rank+","+csv(f.getEntryPoint().toString())+","+csv(displayName(f))+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("failed:"+msg)+",0,false"); continue;}
                Iterator<PcodeOpAST> it=high.getPcodeOps();
                int functionOps=0; boolean truncated=false;
                while(it!=null&&it.hasNext()&&!monitor.isCancelled()){
                    if(functionOps>=maxOpsPerFunction||totalOps>=maxOpsTotal){truncated=true;break;}
                    PcodeOpAST op=it.next();
                    StringBuilder inputs=new StringBuilder();
                    for(int k=0;k<op.getNumInputs();k++){if(k>0)inputs.append(" | ");inputs.append(varnode(op.getInput(k)));}
                    out.println(t.rank+","+csv(f.getEntryPoint().toString())+","+csv(displayName(f))+","+csv(t.mode)+","+csv(t.tier)+","+
                        csv(op.getSeqnum().getTarget().toString())+","+op.getSeqnum().getTime()+","+op.getOpcode()+","+csv(op.getMnemonic())+","+csv(varnode(op.getOutput()))+","+csv(inputs.toString()));
                    functionOps++; totalOps++;
                }
                exported++;
                summary.println(t.rank+","+csv(f.getEntryPoint().toString())+","+csv(displayName(f))+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("ok")+","+functionOps+","+truncated);
            }
        } finally { decomp.dispose(); }

        try(PrintWriter w=writer(new File(outDir,"v51_high_pcode_report.md"))){
            w.println("# V5.1 SSA/high P-code export\n");
            w.println("High P-code is emitted from Ghidra's decompiler syntax tree. Unlike the raw instruction P-code stream, its unique variables and MULTIEQUAL/phi nodes preserve substantially better definition-use structure for backward slicing.\n");
            w.println("- Requested targets: **"+targets.size()+"**");
            w.println("- High-P-code functions exported: **"+exported+"**");
            w.println("- Failed/timeouts: **"+failed+"**");
            w.println("- Total high-P-code ops: **"+totalOps+"**");
            w.println("- Per-function op cap: **"+maxOpsPerFunction+"**");
            w.println("- Decompile timeout/function: **"+timeoutSec+" sec**");
        }
        println("[v5.1] high p-code exported="+exported+" failed="+failed+" ops="+totalOps);
    }

    private List<Target> readTargets(File file,int max)throws Exception{
        List<Target> out=new ArrayList<>();
        try(BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(file),StandardCharsets.UTF_8))){
            String header=br.readLine();if(header==null)return out;List<String> hs=parseCsv(header);
            int entryI=hs.indexOf("entry"),nameI=hs.indexOf("name"),modeI=hs.indexOf("recommended_mode"),tierI=hs.indexOf("v51_priority_tier"),sizeI=hs.indexOf("size_bytes");
            String line;int rank=0;while((line=br.readLine())!=null&&out.size()<max){if(line.trim().isEmpty())continue;List<String>xs=parseCsv(line);Target t=new Target();t.entry=get(xs,entryI);t.name=get(xs,nameI);t.mode=get(xs,modeI);t.tier=get(xs,tierI);t.size=parseInt(get(xs,sizeI),0);t.rank=++rank;if(!t.entry.isEmpty())out.add(t);}
        }return out;
    }
    private Address parseEntryAddress(String s){try{return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(s.trim(),16));}catch(Exception e){return null;}}
    private String displayName(Function f){String n=f==null?"":f.getName();if(n==null||n.isEmpty()||n.startsWith("FUN_")||n.startsWith("LAB_")||n.startsWith("SUB_"))return "sub_"+Long.toHexString(f.getEntryPoint().getOffset()).toUpperCase();return n;}
    private String varnode(Varnode v){return v==null?"":v.toString();}
    private int parseInt(String s,int fallback){try{return Integer.parseInt(s);}catch(Exception e){return fallback;}}
    private PrintWriter writer(File f)throws Exception{return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8)),true);}
    private String csv(String s){if(s==null)return "\"\"";return "\""+s.replace("\"","\"\"").replace("\r"," ").replace("\n","\\n")+"\"";}
    private String get(List<String>xs,int i){return i>=0&&i<xs.size()?xs.get(i):"";}
    private List<String>parseCsv(String line){List<String>out=new ArrayList<>();StringBuilder cur=new StringBuilder();boolean q=false;for(int i=0;i<line.length();i++){char c=line.charAt(i);if(c=='\"'){if(q&&i+1<line.length()&&line.charAt(i+1)=='\"'){cur.append('\"');i++;}else q=!q;}else if(c==','&&!q){out.add(cur.toString());cur.setLength(0);}else cur.append(c);}out.add(cur.toString());return out;}
}
