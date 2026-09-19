// Whole-function C pass across every internal Ghidra function for Mobile Ghidra Lab V5.6.
// @category MobileGhidraLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class ExportV56AllC extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("ExportV56AllC.java <outDir> [timeoutSec]");
        File outDir = new File(args[0]);
        int timeoutSec = args.length >= 2 ? parseInt(args[1], 6) : 6;
        File cDir = new File(outDir, "human/reconstructed_c_v56/all_functions");
        cDir.mkdirs();

        DecompInterface d = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        d.setOptions(opts);
        d.toggleCCode(true);
        d.toggleSyntaxTree(false);
        d.setSimplificationStyle("decompile");
        if (!d.openProgram(currentProgram)) throw new IllegalStateException("Decompiler could not open program");

        int total=0, ok=0, failed=0;
        try (PrintWriter idx = writer(new File(outDir, "v56_all_c_index.csv"));
             PrintWriter retry = writer(new File(outDir, "v56_all_c_fallback.csv"))) {
            idx.println("entry,name,size_bytes,instructions,is_thunk,status,c_file,error");
            retry.println("entry,name,recommended_mode,score,size_bytes,v56_login_boost");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f == null || f.isExternal()) continue;
                total++;
                String entry = canon(f.getEntryPoint().toString());
                String name = displayName(f);
                long size = f.getBody().getNumAddresses();
                int instructions = countInstructions(f);
                String status="failed", err="", rel="";
                try {
                    DecompileResults r = d.decompileFunction(f, timeoutSec, monitor);
                    String c = (r != null && r.decompileCompleted() && r.getDecompiledFunction()!=null) ? r.getDecompiledFunction().getC() : null;
                    if (c != null && !c.trim().isEmpty()) {
                        File cf = new File(cDir, entry + "_" + sanitize(name) + ".c");
                        try (PrintWriter w = writer(cf)) {
                            w.println("/* V5.6 all-function pseudocode reconstructed by Ghidra; not original source. */");
                            w.println("/* entry=0x"+entry+" name="+clean(name)+" size="+size+" instructions="+instructions+" */");
                            w.println(c);
                        }
                        status="ok"; rel="human/reconstructed_c_v56/all_functions/"+cf.getName(); ok++;
                    } else {
                        err=clean(r==null?"no_result":r.getErrorMessage()); failed++;
                    }
                } catch (Exception ex) { err=clean(ex.toString()); failed++; }
                idx.println(csv(entry)+","+csv(name)+","+size+","+instructions+","+f.isThunk()+","+csv(status)+","+csv(rel)+","+csv(err));
                if (!"ok".equals(status)) retry.println(csv(entry)+","+csv(name)+",region,0,"+size+",0");
                if ((total % 500)==0) { idx.flush(); retry.flush(); println("[v5.6-all-c] processed="+total+" ok="+ok+" failed="+failed); }
            }
        } finally { d.dispose(); }
        println("[v5.6-all-c] complete total="+total+" ok="+ok+" failed="+failed);
    }

    private int countInstructions(Function f) {
        int n=0; InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext() && !monitor.isCancelled()){it.next();n++;} return n;
    }
    private String displayName(Function f){String n=f.getName();return (n==null||n.isEmpty())?"sub_"+canon(f.getEntryPoint().toString()):n;}
    private int parseInt(String s,int d){try{return Integer.parseInt(s);}catch(Exception e){return d;}}
    private String canon(String s){s=s==null?"":s.trim();if(s.toLowerCase().startsWith("0x"))s=s.substring(2);try{return String.format("%08X",Long.parseUnsignedLong(s,16));}catch(Exception e){return s.toUpperCase();}}
    private String sanitize(String s){return (s==null?"fn":s).replaceAll("[^A-Za-z0-9_.-]+","_");}
    private String clean(String s){return s==null?"":s.replace('\n',' ').replace('\r',' ').trim();}
    private String csv(String s){s=s==null?"":s;if(s.contains(",")||s.contains("\"")||s.contains("\n"))return "\""+s.replace("\"","\"\"")+"\"";return s;}
    private PrintWriter writer(File f)throws Exception{File p=f.getParentFile();if(p!=null)p.mkdirs();return new PrintWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8));}
}
