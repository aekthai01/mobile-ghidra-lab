// SSA/high P-code exporter for Mobile Ghidra Lab V5.1/V5.5.
// @category MobileGhidraLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportV51HighPcode extends GhidraScript {
    private static class Target { String entry, name, mode, tier; int rank, size; }
    private static class Region { String functionEntry, functionName, id, start, end, reason; }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("ExportV51HighPcode.java <outDir> <selectionCsv> [maxFunctions] [timeoutSec] [maxOpsPerFunction] [maxOpsTotal]");
        File outDir = new File(args[0]);
        File selection = new File(args[1]);
        int maxFunctions = args.length >= 3 ? parseInt(args[2], 120) : 120;
        int timeoutSec = args.length >= 4 ? parseInt(args[3], 12) : 12;
        int maxOpsPerFunction = args.length >= 5 ? parseInt(args[4], 40000) : 40000;
        int maxOpsTotal = args.length >= 6 ? parseInt(args[5], 1000000) : 1000000;
        outDir.mkdirs();

        List<Target> targets = readTargets(selection, maxFunctions);
        Map<String,List<Region>> regionMap = readRegions(new File(outDir, "v4_giant_region_index.csv"));
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        decomp.setOptions(opts);
        decomp.toggleCCode(false);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        if (!decomp.openProgram(currentProgram)) throw new IllegalStateException("Decompiler could not open program");

        int totalOps=0, exported=0, failed=0, skipped=0;
        List<Target> regionFallback = new ArrayList<>();
        try (PrintWriter out=writer(new File(outDir,"v51_high_pcode.csv"));
             PrintWriter summary=writer(new File(outDir,"v51_high_pcode_summary.csv"));
             PrintWriter regionOut=writer(new File(outDir,"v55_region_high_pcode.csv"));
             PrintWriter regionSummary=writer(new File(outDir,"v55_region_high_pcode_summary.csv"))) {
            out.println("rank,function_entry,function_name,mode,tier,sequence_address,sequence_time,opcode,mnemonic,output,inputs");
            summary.println("rank,function_entry,function_name,mode,tier,size_bytes,status,high_pcode_ops,truncated");
            regionOut.println("function_entry,function_name,region_id,start_address,end_address,reason,sequence_address,sequence_time,opcode,mnemonic,output,inputs");
            regionSummary.println("function_entry,function_name,region_id,start_address,end_address,reason,status,high_pcode_ops");

            for (Target t: targets) {
                if (monitor.isCancelled() || totalOps >= maxOpsTotal) break;
                boolean wantsRegion = "region".equalsIgnoreCase(t.mode);
                if (wantsRegion && t.size >= 80000) {
                    skipped++;
                    summary.println(t.rank+","+csv(t.entry)+","+csv(t.name)+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("skipped:extreme_giant")+",0,false");
                    regionFallback.add(t);
                    continue;
                }
                Address a=parseEntryAddress(t.entry);
                Function f=a==null?null:currentProgram.getFunctionManager().getFunctionAt(a);
                if(f==null&&a!=null) f=currentProgram.getFunctionManager().getFunctionContaining(a);
                if(f==null){
                    failed++;
                    summary.println(t.rank+","+csv(t.entry)+","+csv(t.name)+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("missing_function")+",0,false");
                    continue;
                }
                DecompileResults res=decomp.decompileFunction(f,timeoutSec,monitor);
                HighFunction high=res==null?null:res.getHighFunction();
                if(high==null){
                    failed++;
                    String msg=res==null?"no_result":res.getErrorMessage();
                    summary.println(t.rank+","+csv(f.getEntryPoint().toString())+","+csv(displayName(f))+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("failed:"+msg)+",0,false");
                    if (wantsRegion) regionFallback.add(t);
                    continue;
                }
                int[] counts=writeOps(high,out,t.rank,f.getEntryPoint().toString(),displayName(f),t.mode,t.tier,maxOpsPerFunction,maxOpsTotal-totalOps);
                int functionOps=counts[0]; boolean truncated=counts[1]!=0;
                totalOps+=functionOps; exported++;
                summary.println(t.rank+","+csv(f.getEntryPoint().toString())+","+csv(displayName(f))+","+csv(t.mode)+","+csv(t.tier)+","+t.size+","+csv("ok")+","+functionOps+","+truncated);
            }

            int[] regionStats=exportRegionFallbacks(regionFallback,regionMap,decomp,regionOut,regionSummary,Math.max(5,Math.min(timeoutSec,20)),Math.max(2000,Math.min(maxOpsPerFunction,12000)),Math.max(0,maxOpsTotal-totalOps));
            totalOps+=regionStats[2];
            writeReport(outDir,targets,exported,failed,skipped,totalOps,maxOpsPerFunction,timeoutSec,regionStats);
        } finally { decomp.dispose(); }

        println("[v5.5] high p-code whole exported="+exported+" failed="+failed+" skipped="+skipped+" ops="+totalOps);
    }

    private int[] exportRegionFallbacks(List<Target> targets, Map<String,List<Region>> regionMap, DecompInterface decomp,
                                        PrintWriter out, PrintWriter summary, int timeoutSec, int maxOpsPerRegion, int budgetOps) {
        int attempted=0, ok=0, opsTotal=0, failed=0;
        FunctionManager fm=currentProgram.getFunctionManager();
        Set<String> processed=new HashSet<>();
        for(Target t:targets){
            if(monitor.isCancelled()||opsTotal>=budgetOps)break;
            String key=canon(t.entry);
            if(!processed.add(key))continue;
            List<Region> rs=regionMap.getOrDefault(key,Collections.emptyList());
            Address entry=parseEntryAddress(t.entry);
            Function original=entry==null?null:fm.getFunctionAt(entry);
            if(original==null&&entry!=null)original=fm.getFunctionContaining(entry);
            if(original==null||rs.isEmpty()){
                String status=original==null?"missing_function":"missing_region_index";
                summary.println(csv(key)+","+csv(t.name)+",,,,,"+csv(status)+",0");
                failed++;
                continue;
            }
            Address originalEntry=original.getEntryPoint();
            fm.removeFunction(originalEntry);
            decomp.flushCache();
            for(Region r:rs){
                if(monitor.isCancelled()||opsTotal>=budgetOps)break;
                attempted++;
                Address sa=parseEntryAddress(r.start), ea=parseEntryAddress(r.end);
                Instruction si=sa==null?null:currentProgram.getListing().getInstructionContaining(sa);
                Instruction ei=ea==null?null:currentProgram.getListing().getInstructionContaining(ea);
                if(si==null&&sa!=null)si=currentProgram.getListing().getInstructionAt(sa);
                if(ei==null&&ea!=null)ei=currentProgram.getListing().getInstructionAt(ea);
                if(si==null||ei==null){
                    summary.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv(r.reason)+","+csv("missing_instruction")+",0");
                    failed++;
                    continue;
                }
                Address lo=si.getAddress(), hi=ei.getMaxAddress();
                Function temp=null;
                int regionOps=0;
                String status="failed";
                try{
                    AddressSet body=new AddressSet(lo,hi);
                    String tempName="__mgl_r_"+key+"_"+sanitize(r.id);
                    temp=fm.createFunction(tempName,lo,body,SourceType.ANALYSIS);
                    decomp.flushCache();
                    if(temp==null){
                        status="create_function_failed";
                    }else{
                        DecompileResults res=decomp.decompileFunction(temp,timeoutSec,monitor);
                        HighFunction high=res==null?null:res.getHighFunction();
                        if(high==null){
                            status="failed:"+clean(res==null?"no_result":res.getErrorMessage());
                        }else{
                            Iterator<PcodeOpAST> it=high.getPcodeOps();
                            while(it!=null&&it.hasNext()&&!monitor.isCancelled()&&regionOps<maxOpsPerRegion&&opsTotal<budgetOps){
                                PcodeOpAST op=it.next();
                                StringBuilder inputs=new StringBuilder();
                                for(int k=0;k<op.getNumInputs();k++){if(k>0)inputs.append(" | ");inputs.append(varnode(op.getInput(k)));}
                                out.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv(r.reason)+","+
                                    csv(op.getSeqnum().getTarget().toString())+","+op.getSeqnum().getTime()+","+op.getOpcode()+","+csv(op.getMnemonic())+","+csv(varnode(op.getOutput()))+","+csv(inputs.toString()));
                                regionOps++;opsTotal++;
                            }
                            status=regionOps>=maxOpsPerRegion?"ok:truncated":"ok";
                            ok++;
                        }
                    }
                }catch(Exception ex){status="exception:"+clean(ex.toString());}
                finally{
                    if(temp!=null){try{fm.removeFunction(temp.getEntryPoint());}catch(Exception ignored){} decomp.flushCache();}
                }
                if(!status.startsWith("ok"))failed++;
                summary.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv(r.reason)+","+csv(status)+","+regionOps);
            }
        }
        return new int[]{attempted,ok,opsTotal,failed};
    }

    private int[] writeOps(HighFunction high, PrintWriter out, int rank, String entry, String name, String mode, String tier, int maxOps, int budgetOps){
        Iterator<PcodeOpAST> it=high.getPcodeOps(); int n=0; boolean truncated=false;
        while(it!=null&&it.hasNext()&&!monitor.isCancelled()){
            if(n>=maxOps||n>=budgetOps){truncated=true;break;}
            PcodeOpAST op=it.next(); StringBuilder inputs=new StringBuilder();
            for(int k=0;k<op.getNumInputs();k++){if(k>0)inputs.append(" | ");inputs.append(varnode(op.getInput(k)));}
            out.println(rank+","+csv(entry)+","+csv(name)+","+csv(mode)+","+csv(tier)+","+csv(op.getSeqnum().getTarget().toString())+","+op.getSeqnum().getTime()+","+op.getOpcode()+","+csv(op.getMnemonic())+","+csv(varnode(op.getOutput()))+","+csv(inputs.toString()));
            n++;
        }
        return new int[]{n,truncated?1:0};
    }

    private void writeReport(File outDir,List<Target> targets,int exported,int failed,int skipped,int totalOps,int maxOpsPerFunction,int timeoutSec,int[] regionStats)throws Exception{
        try(PrintWriter w=writer(new File(outDir,"v51_high_pcode_report.md"))){
            w.println("# V5.5 SSA/high P-code export\n");
            w.println("Whole-function High P-code is attempted first. Region-mode functions that time out or are extreme giants are retried as bounded temporary region functions after V5.4 lossless evidence has already been exported. The project is disposable and no binary bytes are patched.\n");
            w.println("- Requested targets: **"+targets.size()+"**");
            w.println("- Whole functions exported: **"+exported+"**");
            w.println("- Whole failures/timeouts: **"+failed+"**");
            w.println("- Extreme giants sent to region fallback: **"+skipped+"**");
            w.println("- Region attempts: **"+regionStats[0]+"**");
            w.println("- Region High-P-code successes: **"+regionStats[1]+"**");
            w.println("- Region High-P-code ops: **"+regionStats[2]+"**");
            w.println("- Total High-P-code ops: **"+totalOps+"**");
            w.println("- Whole-function op cap: **"+maxOpsPerFunction+"**");
            w.println("- Whole-function decompile timeout: **"+timeoutSec+" sec**");
        }
    }

    private Map<String,List<Region>> readRegions(File file)throws Exception{
        Map<String,List<Region>> out=new LinkedHashMap<>(); if(!file.isFile())return out;
        try(BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(file),StandardCharsets.UTF_8))){
            String header=br.readLine();if(header==null)return out;List<String>hs=parseCsv(header);
            int fe=hs.indexOf("function_entry"),fn=hs.indexOf("function_name"),ri=hs.indexOf("region_id"),st=hs.indexOf("start_address"),en=hs.indexOf("end_address"),re=hs.indexOf("reason");
            String line;while((line=br.readLine())!=null){if(line.trim().isEmpty())continue;List<String>x=parseCsv(line);Region r=new Region();r.functionEntry=get(x,fe);r.functionName=get(x,fn);r.id=get(x,ri);r.start=get(x,st);r.end=get(x,en);r.reason=get(x,re);String k=canon(r.functionEntry);if(!k.isEmpty())out.computeIfAbsent(k,z->new ArrayList<>()).add(r);}
        }return out;
    }

    private List<Target> readTargets(File file,int max)throws Exception{
        List<Target> out=new ArrayList<>();
        try(BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(file),StandardCharsets.UTF_8))){
            String header=br.readLine();if(header==null)return out;List<String> hs=parseCsv(header);
            int entryI=hs.indexOf("entry"),nameI=hs.indexOf("name"),modeI=hs.indexOf("recommended_mode"),tierI=hs.indexOf("v51_priority_tier"),sizeI=hs.indexOf("size_bytes");
            String line;int rank=0;while((line=br.readLine())!=null&&out.size()<max){if(line.trim().isEmpty())continue;List<String>xs=parseCsv(line);Target t=new Target();t.entry=get(xs,entryI);t.name=get(xs,nameI);t.mode=get(xs,modeI);t.tier=get(xs,tierI);t.size=parseInt(get(xs,sizeI),0);t.rank=++rank;if(!t.entry.isEmpty())out.add(t);}
        }return out;
    }
    private Address parseEntryAddress(String s){try{return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(canon(s),16));}catch(Exception e){return null;}}
    private String canon(String s){if(s==null)return "";String x=s.trim();if(x.startsWith("0x")||x.startsWith("0X"))x=x.substring(2);try{return String.format("%08X",Long.parseUnsignedLong(x,16));}catch(Exception e){return x.toUpperCase();}}
    private String displayName(Function f){String n=f==null?"":f.getName();if(n==null||n.isEmpty()||n.startsWith("FUN_")||n.startsWith("LAB_")||n.startsWith("SUB_"))return "sub_"+Long.toHexString(f.getEntryPoint().getOffset()).toUpperCase();return n;}
    private String varnode(Varnode v){return v==null?"":v.toString();}
    private int parseInt(String s,int fallback){try{return Integer.parseInt(s);}catch(Exception e){return fallback;}}
    private PrintWriter writer(File f)throws Exception{return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8)),true);}
    private String csv(String s){if(s==null)return "\"\"";return "\""+s.replace("\"","\"\"").replace("\r"," ").replace("\n","\\n")+"\"";}
    private String get(List<String>xs,int i){return i>=0&&i<xs.size()?xs.get(i):"";}
    private String sanitize(String s){return (s==null?"r":s).replaceAll("[^A-Za-z0-9_]+","_");}
    private String clean(String s){return (s==null?"":s).replace("\r"," ").replace("\n","\\n");}
    private List<String>parseCsv(String line){List<String>out=new ArrayList<>();StringBuilder cur=new StringBuilder();boolean q=false;for(int i=0;i<line.length();i++){char c=line.charAt(i);if(c=='\"'){if(q&&i+1<line.length()&&line.charAt(i+1)=='\"'){cur.append('\"');i++;}else q=!q;}else if(c==','&&!q){out.add(cur.toString());cur.setLength(0);}else cur.append(c);}out.add(cur.toString());return out;}
}
