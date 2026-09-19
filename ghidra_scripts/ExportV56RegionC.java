// Exhaustive Region-C reconstruction with adaptive subdivision for Mobile Ghidra Lab V5.6.
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
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportV56RegionC extends GhidraScript {
    private static final int BASE_WINDOW = 180;
    private static final int BASE_STEP = 160;
    private static final int MIN_ADAPTIVE_WINDOW = 24;
    private static class Target { String entry, name, mode; int size, rank, loginBoost; }
    private static class Region { String id, start, end, reason; int priority; }
    private static class Attempt { boolean ok; String c=""; String error=""; HighFunction high; }

    private DecompInterface decomp;
    private FunctionManager fm;
    private AddressSet originalBody;
    private String currentKey;
    private int timeoutSec;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("ExportV56RegionC.java <outDir> <selectionCsv> [timeoutSec] [maxOpsPerRetryRegion]");
        File outDir = new File(args[0]);
        File selection = new File(args[1]);
        timeoutSec = args.length >= 3 ? parseInt(args[2], 20) : 20;
        int maxOpsPerRetryRegion = args.length >= 4 ? parseInt(args[3], 20000) : 20000;
        outDir.mkdirs();

        List<Target> targets = readTargets(selection);
        Map<String,Boolean> wholeOk = readWholeStatus(new File(outDir, "v51_high_pcode_summary.csv"));
        Map<String,Boolean> wholeCOk = readWholeCStatus(new File(outDir, "v4_selected_export.csv"), new File(outDir, "v4_decompiled_selected"));
        Map<String,Integer> existingRegionSuccess = readRegionSuccess(new File(outDir, "v55_region_high_pcode_summary.csv"));

        File regionRoot = new File(outDir, "human/reconstructed_c_v56/regions");
        regionRoot.mkdirs();
        File pcodeFile = new File(outDir, "v55_region_high_pcode.csv");
        File pcodeSummaryFile = new File(outDir, "v55_region_high_pcode_summary.csv");
        boolean pcodeNeedsHeader = !pcodeFile.isFile() || pcodeFile.length() == 0;
        boolean summaryNeedsHeader = !pcodeSummaryFile.isFile() || pcodeSummaryFile.length() == 0;

        decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        decomp.setOptions(opts);
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        if (!decomp.openProgram(currentProgram)) throw new IllegalStateException("Decompiler could not open program");
        fm = currentProgram.getFunctionManager();

        int targetCount=0, regionAttempts=0, cSuccess=0, retrySuccess=0;
        try (PrintWriter index=writer(new File(outDir,"v56_region_c_index.csv"));
             PrintWriter pcode=appendWriter(pcodeFile);
             PrintWriter pcodeSummary=appendWriter(pcodeSummaryFile)) {
            index.println("function_entry,function_name,region_id,start_address,end_address,reason,status,c_file,high_pcode_retry_ops,error");
            if (pcodeNeedsHeader) pcode.println("function_entry,function_name,region_id,start_address,end_address,reason,sequence_address,sequence_time,opcode,mnemonic,output,inputs");
            if (summaryNeedsHeader) pcodeSummary.println("function_entry,function_name,region_id,start_address,end_address,reason,status,high_pcode_ops");

            for (Target t: targets) {
                if (monitor.isCancelled()) break;
                currentKey=canon(t.entry);
                boolean wantsRegion="region".equalsIgnoreCase(t.mode);
                boolean wholePcodeOk=Boolean.TRUE.equals(wholeOk.get(currentKey));
                boolean wholeCDecompiled=Boolean.TRUE.equals(wholeCOk.get(currentKey));
                boolean needPcodeRetry=!wholePcodeOk && existingRegionSuccess.getOrDefault(currentKey,0)==0;
                boolean needCFallback=!wholeCDecompiled;
                if (!wantsRegion && !needCFallback && !needPcodeRetry) continue;
                targetCount++;

                List<Region> regions=synthesizeRegions(t);
                if (regions.isEmpty()) {
                    index.println(csv(currentKey)+","+csv(t.name)+",,,,,"+csv("no_regions")+",,0,"+csv("no executable instructions for exhaustive coverage"));
                    continue;
                }

                Address entry=parseMglAddress(currentKey);
                Function original=entry==null?null:fm.getFunctionAt(entry);
                if (original==null && entry!=null) original=fm.getFunctionContaining(entry);
                originalBody=original==null?null:new AddressSet(original.getBody());
                if (original!=null) { try { fm.removeFunction(original.getEntryPoint()); } catch(Exception ignored){} decomp.flushCache(); }

                boolean retrySatisfied=!needPcodeRetry;
                for (Region r: regions) {
                    if (monitor.isCancelled()) break;
                    regionAttempts++;
                    Address sa=parseMglAddress(r.start), ea=parseMglAddress(r.end);
                    Instruction si=sa==null?null:currentProgram.getListing().getInstructionContaining(sa);
                    Instruction ei=ea==null?null:currentProgram.getListing().getInstructionContaining(ea);
                    if (si==null && sa!=null) si=currentProgram.getListing().getInstructionAt(sa);
                    if (ei==null && ea!=null) ei=currentProgram.getListing().getInstructionAt(ea);
                    if (si==null || ei==null) {
                        index.println(csv(currentKey)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv(r.reason)+","+csv("missing_instruction")+",,0,"+csv("region bounds do not resolve to instructions"));
                        continue;
                    }

                    File cFile=new File(regionRoot,currentKey+"_"+sanitize(r.id)+".c");
                    Attempt a=decompileAdaptive(si.getAddress(),ei.getMaxAddress(),r.id,0);
                    int retryOps=0;
                    if (a.ok) {
                        try(PrintWriter cw=writer(cFile)) {
                            cw.println("/* V5.6 region pseudocode reconstructed by Ghidra; not original source. */");
                            cw.println("/* parent=0x"+currentKey+" region="+r.id+" range="+si.getAddress()+".."+ei.getMaxAddress()+" reason="+clean(r.reason)+" */");
                            cw.println(a.c);
                        }
                        cSuccess++;
                    }

                    if (!retrySatisfied && a.high!=null) {
                        Iterator<PcodeOpAST> pit=a.high.getPcodeOps();
                        while(pit!=null && pit.hasNext() && !monitor.isCancelled() && retryOps<maxOpsPerRetryRegion) {
                            PcodeOpAST op=pit.next(); StringBuilder inputs=new StringBuilder();
                            for(int k=0;k<op.getNumInputs();k++){if(k>0)inputs.append(" | ");inputs.append(varnode(op.getInput(k)));}
                            pcode.println(csv(currentKey)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv("v56-retry:"+r.reason)+","+csv(op.getSeqnum().getTarget().toString())+","+op.getSeqnum().getTime()+","+op.getOpcode()+","+csv(op.getMnemonic())+","+csv(varnode(op.getOutput()))+","+csv(inputs.toString()));
                            retryOps++;
                        }
                        if(retryOps>0){pcodeSummary.println(csv(currentKey)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv("v56-retry:"+r.reason)+","+csv("ok")+","+retryOps);retrySatisfied=true;retrySuccess++;}
                    }
                    String status=a.ok?"ok-adaptive":"failed:"+clean(a.error);
                    index.println(csv(currentKey)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv(r.reason)+","+csv(status)+","+csv(a.ok?"human/reconstructed_c_v56/regions/"+cFile.getName():"")+","+retryOps+","+csv(a.error));
                }
            }
        } finally { decomp.dispose(); }
        println("[v5.6] exhaustive region C targets="+targetCount+" attempts="+regionAttempts+" c_success="+cSuccess+" independent_pcode_retries="+retrySuccess);
    }

    private Attempt decompileAdaptive(Address lo, Address hi, String id, int depth) {
        Attempt direct=decompileRange(lo,hi,id+"_d"+depth);
        if(direct.ok) return direct;
        List<Instruction> ins=instructions(lo,hi);
        if(ins.size()<=MIN_ADAPTIVE_WINDOW) return direct;
        int mid=ins.size()/2;
        Address leftLo=ins.get(0).getAddress(), leftHi=ins.get(mid-1).getMaxAddress();
        Address rightLo=ins.get(mid).getAddress(), rightHi=ins.get(ins.size()-1).getMaxAddress();
        Attempt left=decompileAdaptive(leftLo,leftHi,id+"L",depth+1);
        Attempt right=decompileAdaptive(rightLo,rightHi,id+"R",depth+1);
        Attempt out=new Attempt();
        out.high=direct.high!=null?direct.high:(left.high!=null?left.high:right.high);
        if(left.ok && right.ok) {
            out.ok=true;
            out.c="/* adaptive subdivision: "+leftLo+".."+leftHi+" */\n"+left.c+"\n/* adaptive subdivision: "+rightLo+".."+rightHi+" */\n"+right.c;
        } else {
            out.error="adaptive coverage incomplete ["+clean(left.error)+"] ["+clean(right.error)+"]";
        }
        return out;
    }

    private Attempt decompileRange(Address lo, Address hi, String suffix) {
        Attempt out=new Attempt(); Function temp=null;
        try {
            AddressSet bounds=new AddressSet(lo,hi);
            AddressSet body=originalBody==null?bounds:originalBody.intersect(bounds);
            if(body.isEmpty()){out.error="empty_region_body";return out;}
            temp=fm.createFunction("__mgl_v56_"+currentKey+"_"+sanitize(suffix),lo,body,SourceType.ANALYSIS);
            decomp.flushCache();
            if(temp==null){out.error="create_function_failed";return out;}
            DecompileResults res=decomp.decompileFunction(temp,timeoutSec,monitor);
            out.high=res==null?null:res.getHighFunction();
            String c=(res!=null&&res.decompileCompleted()&&res.getDecompiledFunction()!=null)?res.getDecompiledFunction().getC():null;
            if(isMeaningfulC(c)){out.ok=true;out.c=c;} else out.error=clean(res==null?"no_result":res.getErrorMessage());
        } catch(Exception ex){out.error=clean(ex.toString());}
        finally { if(temp!=null){try{fm.removeFunction(temp.getEntryPoint());}catch(Exception ignored){}decomp.flushCache();} }
        return out;
    }

    private boolean isMeaningfulC(String c){if(c==null||c.trim().length()<40)return false;String x=c.replaceAll("(?s)/\\*.*?\\*/","").trim();return x.contains("{")&&x.contains("}")&&x.contains("(")&&x.contains(")")&&(x.contains("=")||x.contains("return")||x.contains("if (")||x.contains("if(")||x.contains("goto ")||x.contains("FUN_")||x.contains("sub_"));}
    private List<Instruction> instructions(Address lo,Address hi){List<Instruction> out=new ArrayList<>();InstructionIterator it=currentProgram.getListing().getInstructions(new AddressSet(lo,hi),true);while(it.hasNext()&&!monitor.isCancelled())out.add(it.next());return out;}

    private List<Region> synthesizeRegions(Target t){
        List<Region> out=new ArrayList<>(); Address start=parseMglAddress(t.entry); if(start==null)return out;
        Function f=fm.getFunctionAt(start); if(f==null)f=fm.getFunctionContaining(start); AddressSet coverage;
        if(f!=null)coverage=new AddressSet(f.getBody()); else {if(t.size<=0)return out;try{coverage=new AddressSet(start,start.add(Math.max(0,t.size-1)));}catch(Exception e){return out;}}
        InstructionIterator it=currentProgram.getListing().getInstructions(coverage,true);List<Instruction> ins=new ArrayList<>();while(it.hasNext()&&!monitor.isCancelled())ins.add(it.next());if(ins.isEmpty())return out;
        int id=0;for(int i=0;i<ins.size();i+=BASE_STEP){int hi=Math.min(ins.size()-1,i+BASE_WINDOW-1);Region r=new Region();r.id=String.format("C%04d",++id);r.start=ins.get(i).getAddress().toString();r.end=ins.get(hi).getAddress().toString();boolean seed=containsImmediate2712(ins,i,hi);r.priority=seed?0:1;r.reason=seed?"v56-exhaustive-coverage+login-seed-0x2712":"v56-exhaustive-coverage";out.add(r);if(hi==ins.size()-1)break;}out.sort(Comparator.comparingInt(r->r.priority));return out;
    }
    private boolean containsImmediate2712(List<Instruction> ins,int lo,int hi){for(int i=lo;i<=hi&&i<ins.size();i++){Instruction x=ins.get(i);for(int op=0;op<x.getNumOperands();op++){try{Scalar s=x.getScalar(op);if(s!=null&&s.getUnsignedValue()==0x2712L)return true;}catch(Exception ignored){}}}return false;}

    private Map<String,Boolean> readWholeStatus(File file)throws Exception{Map<String,Boolean>out=new HashMap<>();for(Map<String,String>r:readCsv(file)){String e=canon(r.get("function_entry"));boolean ok="ok".equalsIgnoreCase(r.get("status"))&&parseInt(r.get("high_pcode_ops"),0)>0;if(!e.isEmpty())out.put(e,ok);}return out;}
    private Map<String,Boolean> readWholeCStatus(File file,File cDir)throws Exception{Map<String,Boolean>out=new HashMap<>();Set<String>meaningful=new HashSet<>();if(cDir.isDirectory()){File[]fs=cDir.listFiles((d,n)->n.endsWith(".c"));if(fs!=null)for(File f:fs){String text=readText(f);java.util.regex.Matcher m=java.util.regex.Pattern.compile("\\bentry=([0-9A-Fa-fx]+)").matcher(text);if(m.find()&&isMeaningfulC(text))meaningful.add(canon(m.group(1)));}}for(Map<String,String>r:readCsv(file)){String e=canon(r.get("entry"));boolean ok="ok".equalsIgnoreCase(r.get("decompile_status"))&&meaningful.contains(e);if(!e.isEmpty())out.put(e,ok);}return out;}
    private Map<String,Integer> readRegionSuccess(File file)throws Exception{Map<String,Integer>out=new HashMap<>();for(Map<String,String>r:readCsv(file)){String e=canon(r.get("function_entry"));boolean ok=(r.get("status")==null?"":r.get("status")).toLowerCase().startsWith("ok");if(ok&&parseInt(r.get("high_pcode_ops"),0)>0)out.put(e,out.getOrDefault(e,0)+1);}return out;}
    private List<Target> readTargets(File file)throws Exception{List<Target>out=new ArrayList<>();int rank=0;for(Map<String,String>r:readCsv(file)){Target t=new Target();t.entry=r.getOrDefault("entry","");t.name=r.getOrDefault("name","");t.mode=r.getOrDefault("recommended_mode","");t.size=parseInt(r.get("size_bytes"),0);t.loginBoost=parseInt(r.get("v56_login_boost"),0);t.rank=++rank;if(!t.entry.isEmpty())out.add(t);}return out;}
    private List<Map<String,String>> readCsv(File file)throws Exception{List<Map<String,String>>out=new ArrayList<>();if(!file.isFile()||file.length()==0)return out;try(BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(file),StandardCharsets.UTF_8))){String h=br.readLine();if(h==null)return out;List<String>hs=parseCsv(h);String line;while((line=br.readLine())!=null){if(line.trim().isEmpty())continue;List<String>xs=parseCsv(line);Map<String,String>r=new LinkedHashMap<>();for(int i=0;i<hs.size();i++)r.put(hs.get(i),get(xs,i));out.add(r);}}return out;}
    private String readText(File f)throws Exception{StringBuilder b=new StringBuilder();try(BufferedReader r=new BufferedReader(new InputStreamReader(new FileInputStream(f),StandardCharsets.UTF_8))){String s;while((s=r.readLine())!=null)b.append(s).append('\n');}return b.toString();}
    private Address parseMglAddress(String s){try{return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(canon(s),16));}catch(Exception e){return null;}}
    private String canon(String s){if(s==null)return"";String x=s.trim();if(x.startsWith("0x")||x.startsWith("0X"))x=x.substring(2);try{return String.format("%08X",Long.parseUnsignedLong(x,16));}catch(Exception e){return x.toUpperCase();}}
    private String varnode(Varnode v){return v==null?"":v.toString();}
    private int parseInt(String s,int fallback){try{return Integer.parseInt(s==null?"":s);}catch(Exception e){return fallback;}}
    private PrintWriter writer(File f)throws Exception{File p=f.getParentFile();if(p!=null)p.mkdirs();return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8)),true);}
    private PrintWriter appendWriter(File f)throws Exception{File p=f.getParentFile();if(p!=null)p.mkdirs();return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f,true),StandardCharsets.UTF_8)),true);}
    private String csv(String s){if(s==null)return"\"\"";return"\""+s.replace("\"","\"\"").replace("\r"," ").replace("\n","\\n")+"\"";}
    private String clean(String s){return(s==null?"":s).replace("\r"," ").replace("\n","\\n");}
    private String sanitize(String s){return(s==null?"r":s).replaceAll("[^A-Za-z0-9_]+","_");}
    private String get(List<String>xs,int i){return i>=0&&i<xs.size()?xs.get(i):"";}
    private List<String> parseCsv(String line){List<String>out=new ArrayList<>();StringBuilder cur=new StringBuilder();boolean q=false;for(int i=0;i<line.length();i++){char c=line.charAt(i);if(c=='\"'){if(q&&i+1<line.length()&&line.charAt(i+1)=='\"'){cur.append('\"');i++;}else q=!q;}else if(c==','&&!q){out.add(cur.toString());cur.setLength(0);}else cur.append(c);}out.add(cur.toString());return out;}
}
