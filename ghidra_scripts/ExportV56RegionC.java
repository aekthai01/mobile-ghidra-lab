// Region C reconstruction + independent High-P-code retry for Mobile Ghidra Lab V5.6.
// Runs after ExportV51HighPcode so the fallback budget is independent from whole-function P-code.
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
import ghidra.program.model.symbol.SourceType;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportV56RegionC extends GhidraScript {
    private static class Target { String entry, name, mode; int size, rank, loginBoost; }
    private static class Region { String id, start, end, reason; }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("ExportV56RegionC.java <outDir> <selectionCsv> [timeoutSec] [maxOpsPerRetryRegion]");
        File outDir = new File(args[0]);
        File selection = new File(args[1]);
        int timeoutSec = args.length >= 3 ? parseInt(args[2], 20) : 20;
        int maxOpsPerRetryRegion = args.length >= 4 ? parseInt(args[3], 20000) : 20000;
        outDir.mkdirs();

        List<Target> targets = readTargets(selection);
        Map<String,List<Region>> regionMap = readRegions(new File(outDir, "v4_giant_region_index.csv"));
        Map<String,Boolean> wholeOk = readWholeStatus(new File(outDir, "v51_high_pcode_summary.csv"));
        Map<String,Integer> existingRegionSuccess = readRegionSuccess(new File(outDir, "v55_region_high_pcode_summary.csv"));

        File humanRoot = new File(outDir, "human/reconstructed_c_v56");
        File regionRoot = new File(humanRoot, "regions");
        regionRoot.mkdirs();

        File pcodeFile = new File(outDir, "v55_region_high_pcode.csv");
        File pcodeSummaryFile = new File(outDir, "v55_region_high_pcode_summary.csv");
        boolean pcodeNeedsHeader = !pcodeFile.isFile() || pcodeFile.length() == 0;
        boolean summaryNeedsHeader = !pcodeSummaryFile.isFile() || pcodeSummaryFile.length() == 0;

        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        decomp.setOptions(opts);
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        if (!decomp.openProgram(currentProgram)) throw new IllegalStateException("Decompiler could not open program");

        int targetCount = 0, regionAttempts = 0, cSuccess = 0, retrySuccess = 0;
        try (PrintWriter index = writer(new File(outDir, "v56_region_c_index.csv"));
             PrintWriter pcode = appendWriter(pcodeFile);
             PrintWriter pcodeSummary = appendWriter(pcodeSummaryFile)) {
            index.println("function_entry,function_name,region_id,start_address,end_address,reason,status,c_file,high_pcode_retry_ops,error");
            if (pcodeNeedsHeader) pcode.println("function_entry,function_name,region_id,start_address,end_address,reason,sequence_address,sequence_time,opcode,mnemonic,output,inputs");
            if (summaryNeedsHeader) pcodeSummary.println("function_entry,function_name,region_id,start_address,end_address,reason,status,high_pcode_ops");

            for (Target t : targets) {
                if (monitor.isCancelled()) break;
                if (!"region".equalsIgnoreCase(t.mode)) continue;
                String key = canon(t.entry);
                boolean needRetry = !Boolean.TRUE.equals(wholeOk.get(key)) && existingRegionSuccess.getOrDefault(key, 0) == 0;
                if (t.loginBoost <= 0 && !needRetry) continue;
                targetCount++;
                List<Region> regions = new ArrayList<>(regionMap.getOrDefault(key, Collections.emptyList()));
                if (regions.isEmpty()) regions = synthesizeRegions(t);
                if (regions.isEmpty()) {
                    index.println(csv(key)+","+csv(t.name)+",,,,,"+csv("no_regions")+",,0,"+csv("no region index and no executable instructions"));
                    continue;
                }

                FunctionManager fm = currentProgram.getFunctionManager();
                Address entry = parseMglAddress(key);
                Function original = entry == null ? null : fm.getFunctionAt(entry);
                if (original == null && entry != null) original = fm.getFunctionContaining(entry);
                if (original != null) {
                    try { fm.removeFunction(original.getEntryPoint()); } catch (Exception ignored) {}
                    decomp.flushCache();
                }

                boolean retrySatisfied = !needRetry;
                for (Region r : regions) {
                    if (monitor.isCancelled()) break;
                    regionAttempts++;
                    Address sa = parseMglAddress(r.start), ea = parseMglAddress(r.end);
                    Instruction si = sa == null ? null : currentProgram.getListing().getInstructionContaining(sa);
                    Instruction ei = ea == null ? null : currentProgram.getListing().getInstructionContaining(ea);
                    if (si == null && sa != null) si = currentProgram.getListing().getInstructionAt(sa);
                    if (ei == null && ea != null) ei = currentProgram.getListing().getInstructionAt(ea);
                    if (si == null || ei == null) {
                        index.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv(r.reason)+","+csv("missing_instruction")+",,0,"+csv("region bounds do not resolve to instructions"));
                        continue;
                    }

                    Address lo = si.getAddress(), hi = ei.getMaxAddress();
                    Function temp = null;
                    String status = "failed", error = "";
                    int retryOps = 0;
                    File cFile = new File(regionRoot, key + "_" + sanitize(r.id) + ".c");
                    try {
                        AddressSet body = new AddressSet(lo, hi);
                        temp = fm.createFunction("__mgl_v56_" + key + "_" + sanitize(r.id), lo, body, SourceType.ANALYSIS);
                        decomp.flushCache();
                        if (temp == null) {
                            status = "create_function_failed";
                        } else {
                            DecompileResults res = decomp.decompileFunction(temp, timeoutSec, monitor);
                            HighFunction high = res == null ? null : res.getHighFunction();
                            String c = (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) ? res.getDecompiledFunction().getC() : null;
                            if (c != null && !c.trim().isEmpty()) {
                                try (PrintWriter cw = writer(cFile)) {
                                    cw.println("/* V5.6 region pseudocode reconstructed by Ghidra; not original source. */");
                                    cw.println("/* parent=0x" + key + " region=" + r.id + " range=" + lo + ".." + hi + " reason=" + clean(r.reason) + " */");
                                    cw.println(c);
                                }
                                status = "ok";
                                cSuccess++;
                            } else {
                                status = "failed:" + clean(res == null ? "no_result" : res.getErrorMessage());
                            }

                            if (!retrySatisfied && high != null) {
                                Iterator<PcodeOpAST> pit = high.getPcodeOps();
                                while (pit != null && pit.hasNext() && !monitor.isCancelled() && retryOps < maxOpsPerRetryRegion) {
                                    PcodeOpAST op = pit.next();
                                    StringBuilder inputs = new StringBuilder();
                                    for (int k=0;k<op.getNumInputs();k++) { if (k>0) inputs.append(" | "); inputs.append(varnode(op.getInput(k))); }
                                    pcode.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv("v56-retry:"+r.reason)+","+
                                        csv(op.getSeqnum().getTarget().toString())+","+op.getSeqnum().getTime()+","+op.getOpcode()+","+csv(op.getMnemonic())+","+csv(varnode(op.getOutput()))+","+csv(inputs.toString()));
                                    retryOps++;
                                }
                                if (retryOps > 0) {
                                    pcodeSummary.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv("v56-retry:"+r.reason)+","+csv("ok")+","+retryOps);
                                    retrySatisfied = true;
                                    retrySuccess++;
                                } else {
                                    pcodeSummary.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv("v56-retry:"+r.reason)+","+csv("failed:no_high_function")+",0");
                                }
                            }
                        }
                    } catch (Exception ex) {
                        status = "exception";
                        error = clean(ex.toString());
                    } finally {
                        if (temp != null) {
                            try { fm.removeFunction(temp.getEntryPoint()); } catch (Exception ignored) {}
                            decomp.flushCache();
                        }
                    }
                    index.println(csv(key)+","+csv(t.name)+","+csv(r.id)+","+csv(r.start)+","+csv(r.end)+","+csv(r.reason)+","+csv(status)+","+
                        csv(cFile.isFile() ? "human/reconstructed_c_v56/regions/" + cFile.getName() : "")+","+retryOps+","+csv(error));
                }
            }
        } finally {
            decomp.dispose();
        }
        println("[v5.6] region C targets="+targetCount+" attempts="+regionAttempts+" c_success="+cSuccess+" independent_pcode_retries="+retrySuccess);
    }

    private List<Region> synthesizeRegions(Target t) {
        List<Region> out = new ArrayList<>();
        Address start = parseMglAddress(t.entry);
        if (start == null || t.size <= 0) return out;
        Address end;
        try { end = start.add(Math.max(0, t.size - 1)); } catch (Exception e) { return out; }
        AddressSet set = new AddressSet(start, end);
        InstructionIterator it = currentProgram.getListing().getInstructions(set, true);
        List<Instruction> ins = new ArrayList<>();
        while (it.hasNext() && !monitor.isCancelled()) ins.add(it.next());
        final int window = 140, step = 120;
        int id = 0;
        for (int i=0; i<ins.size(); i+=step) {
            int hi = Math.min(ins.size()-1, i+window-1);
            Region r = new Region();
            r.id = String.format("S%03d", ++id);
            r.start = ins.get(i).getAddress().toString();
            r.end = ins.get(hi).getAddress().toString();
            r.reason = "v56-synthesized-coverage";
            out.add(r);
            if (hi == ins.size()-1) break;
        }
        return out;
    }

    private Map<String,Boolean> readWholeStatus(File file) throws Exception {
        Map<String,Boolean> out = new HashMap<>();
        for (Map<String,String> r : readCsv(file)) {
            String e = canon(r.get("function_entry"));
            boolean ok = "ok".equalsIgnoreCase(r.get("status")) && parseInt(r.get("high_pcode_ops"),0) > 0;
            if (!e.isEmpty()) out.put(e, ok);
        }
        return out;
    }
    private Map<String,Integer> readRegionSuccess(File file) throws Exception {
        Map<String,Integer> out = new HashMap<>();
        for (Map<String,String> r : readCsv(file)) {
            String e = canon(r.get("function_entry"));
            boolean ok = (r.get("status") == null ? "" : r.get("status")).toLowerCase().startsWith("ok");
            if (ok && parseInt(r.get("high_pcode_ops"),0) > 0) out.put(e, out.getOrDefault(e,0)+1);
        }
        return out;
    }

    private List<Target> readTargets(File file) throws Exception {
        List<Target> out = new ArrayList<>(); int rank=0;
        for (Map<String,String> r : readCsv(file)) {
            Target t = new Target();
            t.entry=r.getOrDefault("entry",""); t.name=r.getOrDefault("name",""); t.mode=r.getOrDefault("recommended_mode","");
            t.size=parseInt(r.get("size_bytes"),0); t.loginBoost=parseInt(r.get("v56_login_boost"),0); t.rank=++rank;
            if (!t.entry.isEmpty()) out.add(t);
        }
        return out;
    }
    private Map<String,List<Region>> readRegions(File file) throws Exception {
        Map<String,List<Region>> out = new LinkedHashMap<>();
        for (Map<String,String> q : readCsv(file)) {
            String e=canon(q.get("function_entry")); if(e.isEmpty()) continue;
            Region r=new Region(); r.id=q.getOrDefault("region_id",""); r.start=q.getOrDefault("start_address",""); r.end=q.getOrDefault("end_address",""); r.reason=q.getOrDefault("reason","");
            out.computeIfAbsent(e,z->new ArrayList<>()).add(r);
        }
        return out;
    }
    private List<Map<String,String>> readCsv(File file) throws Exception {
        List<Map<String,String>> out=new ArrayList<>(); if(!file.isFile()||file.length()==0)return out;
        try(BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(file),StandardCharsets.UTF_8))){
            String h=br.readLine(); if(h==null)return out; List<String> hs=parseCsv(h); String line;
            while((line=br.readLine())!=null){if(line.trim().isEmpty())continue;List<String> xs=parseCsv(line);Map<String,String> r=new LinkedHashMap<>();for(int i=0;i<hs.size();i++)r.put(hs.get(i),get(xs,i));out.add(r);}
        } return out;
    }
    private Address parseMglAddress(String s){try{return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(canon(s),16));}catch(Exception e){return null;}}
    private String canon(String s){if(s==null)return "";String x=s.trim();if(x.startsWith("0x")||x.startsWith("0X"))x=x.substring(2);try{return String.format("%08X",Long.parseUnsignedLong(x,16));}catch(Exception e){return x.toUpperCase();}}
    private String varnode(Varnode v){return v==null?"":v.toString();}
    private int parseInt(String s,int fallback){try{return Integer.parseInt(s==null?"":s);}catch(Exception e){return fallback;}}
    private PrintWriter writer(File f)throws Exception{File p=f.getParentFile();if(p!=null)p.mkdirs();return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8)),true);}
    private PrintWriter appendWriter(File f)throws Exception{File p=f.getParentFile();if(p!=null)p.mkdirs();return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f,true),StandardCharsets.UTF_8)),true);}
    private String csv(String s){if(s==null)return "\"\"";return "\""+s.replace("\"","\"\"").replace("\r"," ").replace("\n","\\n")+"\"";}
    private String clean(String s){return (s==null?"":s).replace("\r"," ").replace("\n","\\n");}
    private String sanitize(String s){return (s==null?"r":s).replaceAll("[^A-Za-z0-9_]+","_");}
    private String get(List<String> xs,int i){return i>=0&&i<xs.size()?xs.get(i):"";}
    private List<String> parseCsv(String line){List<String>out=new ArrayList<>();StringBuilder cur=new StringBuilder();boolean q=false;for(int i=0;i<line.length();i++){char c=line.charAt(i);if(c=='\"'){if(q&&i+1<line.length()&&line.charAt(i+1)=='\"'){cur.append('\"');i++;}else q=!q;}else if(c==','&&!q){out.add(cur.toString());cur.setLength(0);}else cur.append(c);}out.add(cur.toString());return out;}
}
