// Lossless protected-function evidence exporter for Mobile Ghidra Lab V5.4.
// @category MobileGhidraLab

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.DefinedDataIterator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPOutputStream;

public class ExportV54ProtectedEvidence extends GhidraScript {
    private static class Target { String entry, name, priority, score, size; }
    private File root;

    @Override
    protected void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length<2) throw new IllegalArgumentException("ExportV54ProtectedEvidence.java <outDir> <protectedCsv>");
        File outDir=new File(args[0]); File csvFile=new File(args[1]);
        root=new File(outDir,"v54_protected_evidence"); root.mkdirs();
        List<Target> targets=readHighTargets(csvFile);
        println("[v5.4] high-protection targets="+targets.size());

        try(PrintWriter sum=writer(new File(outDir,"v54_protected_evidence_summary.csv"))){
            sum.println("entry,name,priority,score,size_bytes,status,instructions,raw_pcode_ops,string_refs,calls,evidence_dir");
            for(Target t:targets){
                if(monitor.isCancelled()) break;
                Address a=parseHexAddress(t.entry);
                Function f=a==null?null:currentProgram.getFunctionManager().getFunctionAt(a);
                if(f==null&&a!=null) f=currentProgram.getFunctionManager().getFunctionContaining(a);
                if(f==null){
                    sum.println(csv(t.entry)+","+csv(t.name)+","+csv(t.priority)+","+csv(t.score)+","+csv(t.size)+",missing,0,0,0,0,");
                    continue;
                }
                String entry=canon(f.getEntryPoint());
                String safe=entry+"_"+sanitize(displayName(f));
                File dir=new File(root,safe); dir.mkdirs();
                List<Instruction> ins=instructions(f);
                int strings=writeArm64AndStrings(f,ins,dir);
                long ops=writeRawPcode(f,ins,new File(dir,"raw_pcode.csv.gz"));
                int calls=writeCalls(f,ins,new File(dir,"calls.csv"));
                writeMetadata(f,t,ins.size(),ops,strings,calls,new File(dir,"metadata.txt"));
                sum.println(csv(entry)+","+csv(displayName(f))+","+csv(t.priority)+","+csv(t.score)+","+f.getBody().getNumAddresses()+",ok,"+ins.size()+","+ops+","+strings+","+calls+","+csv("v54_protected_evidence/"+safe));
            }
        }
        println("[v5.4] protected evidence export complete");
    }

    private List<Target> readHighTargets(File file)throws Exception{
        List<Target> out=new ArrayList<>();
        try(BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(file),StandardCharsets.UTF_8))){
            String h=br.readLine(); if(h==null)return out; List<String> hs=parseCsv(h);
            int ei=hs.indexOf("entry"),ni=hs.indexOf("name"),pi=hs.indexOf("complexity_priority"),si=hs.indexOf("complexity_priority_score"),zi=hs.indexOf("size_bytes");
            String line; while((line=br.readLine())!=null){ if(line.trim().isEmpty())continue; List<String>x=parseCsv(line); if(!"high".equalsIgnoreCase(get(x,pi)))continue;
                Target t=new Target(); t.entry=get(x,ei); t.name=get(x,ni); t.priority=get(x,pi); t.score=get(x,si); t.size=get(x,zi); if(!t.entry.isEmpty())out.add(t);
            }
        }
        return out;
    }

    private int writeArm64AndStrings(Function f,List<Instruction> ins,File dir)throws Exception{
        List<List<String>> comments=new ArrayList<>(); for(int i=0;i<ins.size();i++)comments.add(new ArrayList<>());
        int stringRefs=0;
        for(int i=0;i<ins.size();i++){
            Instruction x=ins.get(i); List<String> exact=stringComments(x);
            if(!exact.isEmpty()){
                stringRefs+=exact.size(); comments.get(i).addAll(exact);
                String m=upper(x.getMnemonicString());
                if("ADD".equals(m)){
                    String reg=firstReg(x);
                    if(!reg.isEmpty()) for(int j=i-1;j>=0&&j>=i-4;j--){
                        String pm=upper(ins.get(j).getMnemonicString());
                        if(("ADRP".equals(pm)||"ADR".equals(pm))&&reg.equals(firstReg(ins.get(j)))){ for(String s:exact) if(!comments.get(j).contains(s))comments.get(j).add(s); break; }
                    }
                }
            }
            String cc=charImmediate(x); if(!cc.isEmpty())comments.get(i).add(cc);
        }
        try(PrintWriter w=writer(new File(dir,"full_arm64_strings.asm"))){
            w.println("; Mobile Ghidra Lab V5.4 - FULL protected-function ARM64 evidence");
            w.println("; No instruction-window truncation. Strings are attached only from Ghidra xrefs or printable immediates.");
            w.println("; FUNCTION "+displayName(f)+" entry=0x"+canon(f.getEntryPoint())+" size=0x"+Long.toHexString(f.getBody().getNumAddresses()).toUpperCase());
            w.println();
            for(int i=0;i<ins.size();i++){
                Instruction x=ins.get(i); String c=comments.get(i).isEmpty()?"":" ; "+String.join(" | ",comments.get(i));
                w.printf(".text:%016X  %-13s %-9s %s%s%n",x.getAddress().getOffset(),bytes(x),upper(x.getMnemonicString()),operands(x),c);
            }
        }
        try(PrintWriter sw=writer(new File(dir,"strings.csv"))){
            sw.println("instruction_address,string_address,value");
            Set<String> seen=new LinkedHashSet<>();
            for(Instruction x:ins) for(Reference r:x.getReferencesFrom()){
                String v=stringAt(r.getToAddress()); if(v==null)continue; String key=canon(x.getAddress())+"|"+canon(r.getToAddress())+"|"+v; if(!seen.add(key))continue;
                sw.println(csv(canon(x.getAddress()))+","+csv(canon(r.getToAddress()))+","+csv(v));
            }
        }
        return stringRefs;
    }

    private long writeRawPcode(Function f,List<Instruction> ins,File file)throws Exception{
        long count=0;
        try(PrintWriter w=gzipWriter(file)){
            w.println("instruction_address,pcode_index,opcode,mnemonic,output,inputs");
            for(Instruction x:ins){
                PcodeOp[] ops=x.getPcode(); if(ops==null)continue;
                for(int i=0;i<ops.length;i++){
                    PcodeOp op=ops[i]; StringBuilder in=new StringBuilder();
                    for(int k=0;k<op.getNumInputs();k++){if(k>0)in.append(" | "); in.append(varnode(op.getInput(k)));}
                    w.println(csv(canon(x.getAddress()))+","+i+","+op.getOpcode()+","+csv(op.getMnemonic())+","+csv(varnode(op.getOutput()))+","+csv(in.toString())); count++;
                }
            }
        }
        return count;
    }

    private int writeCalls(Function f,List<Instruction> ins,File file)throws Exception{
        int n=0;
        try(PrintWriter w=writer(file)){
            w.println("callsite,flow_type,target_address,target_name");
            for(Instruction x:ins){ if(!x.getFlowType().isCall())continue; Address[] fs=x.getFlows();
                if(fs==null||fs.length==0){w.println(csv(canon(x.getAddress()))+","+csv(x.getFlowType().toString())+",,"+csv("<computed>"));n++;continue;}
                for(Address a:fs){ Function cf=a==null?null:currentProgram.getFunctionManager().getFunctionAt(a); w.println(csv(canon(x.getAddress()))+","+csv(x.getFlowType().toString())+","+csv(a==null?"":canon(a))+","+csv(cf==null?(a==null?"<unknown>":"loc_"+canon(a)):displayName(cf))); n++; }
            }
        }
        return n;
    }

    private void writeMetadata(Function f,Target t,int ins,long ops,int strings,int calls,File file)throws Exception{
        try(PrintWriter w=writer(file)){
            w.println("entry=0x"+canon(f.getEntryPoint())); w.println("name="+displayName(f)); w.println("protection="+t.priority); w.println("protection_score="+t.score);
            w.println("size_bytes="+f.getBody().getNumAddresses()); w.println("instructions="+ins); w.println("raw_pcode_ops="+ops); w.println("string_refs="+strings); w.println("calls="+calls);
            w.println("policy=full-evidence-no-window-truncation");
        }
    }

    private List<Instruction> instructions(Function f){List<Instruction>o=new ArrayList<>();InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);while(it.hasNext()&&!monitor.isCancelled())o.add(it.next());return o;}
    private List<String> stringComments(Instruction x){List<String>o=new ArrayList<>();Set<String>s=new LinkedHashSet<>();for(Reference r:x.getReferencesFrom()){String v=stringAt(r.getToAddress());if(v==null)continue;String z=label(v,r.getToAddress())+"@0x"+canon(r.getToAddress())+" = \""+display(v,180)+"\"";if(s.add(z))o.add(z);}return o;}
    private String stringAt(Address a){try{Data d=currentProgram.getListing().getDataContaining(a);if(d==null||!StringDataInstance.isString(d))return null;String v=d.getDefaultValueRepresentation();if(v==null)return null;if(v.length()>4096)v=v.substring(0,4096)+"...[truncated-display]";return trimQuotes(v);}catch(Exception e){return null;}}
    private String label(String v,Address a){String[]w=trimQuotes(v).replaceAll("[^A-Za-z0-9]+"," ").trim().split(" +");StringBuilder b=new StringBuilder("a");for(int i=0;i<w.length&&i<5;i++){if(w[i].isEmpty())continue;b.append(Character.toUpperCase(w[i].charAt(0))).append(w[i].substring(1));if(b.length()>34)break;}return b.length()==1?"str_"+canon(a):b.substring(0,Math.min(35,b.length()));}
    private String display(String s,int max){String x=trimQuotes(s).replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");return x.length()<=max?x:x.substring(0,max-3)+"...";}
    private String charImmediate(Instruction x){String m=upper(x.getMnemonicString());if(!("MOV".equals(m)||"MOVZ".equals(m)))return "";if(x.getNumOperands()<2)return "";String s=x.getDefaultOperandRepresentation(1);if(s==null)return "";s=s.replace("#","").trim();try{int v=s.startsWith("0x")||s.startsWith("0X")?Integer.parseUnsignedInt(s.substring(2),16):Integer.parseInt(s);if(v>=32&&v<=126)return "CHAR '"+((char)v==39?"\\'":Character.toString((char)v))+"'";}catch(Exception e){}return "";}
    private String firstReg(Instruction x){try{if(x.getNumOperands()<1)return "";String s=x.getDefaultOperandRepresentation(0);if(s==null)return "";s=s.trim().toUpperCase();return s.matches("[XW][0-9]{1,2}|SP")?s:"";}catch(Exception e){return "";}}
    private String operands(Instruction x){List<String>o=new ArrayList<>();for(int i=0;i<x.getNumOperands();i++){String s;try{s=x.getDefaultOperandRepresentation(i);}catch(Exception e){s="?";}o.add(s==null?"":s);}Address[]fs=x.getFlows();if((x.getFlowType().isCall()||x.getFlowType().isJump())&&fs!=null&&fs.length==1&&!o.isEmpty()){Address a=fs[0];if(a!=null&&a!=Address.NO_ADDRESS){Function cf=currentProgram.getFunctionManager().getFunctionAt(a);o.set(o.size()-1,cf!=null?displayName(cf):"loc_"+canon(a));}}return String.join(", ",o);}
    private String bytes(Instruction x){try{byte[]b=x.getBytes();StringBuilder s=new StringBuilder();for(int i=0;i<b.length;i++){if(i>0)s.append(' ');s.append(String.format("%02X",b[i]&255));}return s.toString();}catch(Exception e){return "??";}}
    private String varnode(Varnode v){return v==null?"":v.toString();}
    private String displayName(Function f){String n=f==null?"":f.getName();if(n==null||n.isEmpty()||n.startsWith("FUN_")||n.startsWith("LAB_")||n.startsWith("SUB_"))return "sub_"+canon(f.getEntryPoint());return n;}
    private Address parseHexAddress(String s){try{return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(s.trim(),16));}catch(Exception e){return null;}}
    private String canon(Address a){return String.format("%08X",a.getOffset());}
    private String sanitize(String s){String x=(s==null?"function":s).replaceAll("[^A-Za-z0-9._-]+","_");return x.length()>80?x.substring(0,80):x;}
    private String upper(String s){return s==null?"":s.toUpperCase();}
    private String trimQuotes(String s){String x=s==null?"":s.trim();if(x.length()>=2&&x.startsWith("\"")&&x.endsWith("\""))x=x.substring(1,x.length()-1);return x;}
    private PrintWriter writer(File f)throws Exception{return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8)),true);}
    private PrintWriter gzipWriter(File f)throws Exception{return new PrintWriter(new BufferedWriter(new OutputStreamWriter(new GZIPOutputStream(new FileOutputStream(f),65536),StandardCharsets.UTF_8)),true);}
    private String csv(String s){if(s==null)s="";return "\""+s.replace("\"","\"\"").replace("\r"," ").replace("\n","\\n")+"\"";}
    private String get(List<String>x,int i){return i>=0&&i<x.size()?x.get(i):"";}
    private List<String> parseCsv(String line){List<String>o=new ArrayList<>();StringBuilder c=new StringBuilder();boolean q=false;for(int i=0;i<line.length();i++){char ch=line.charAt(i);if(ch=='\"'){if(q&&i+1<line.length()&&line.charAt(i+1)=='\"'){c.append('\"');i++;}else q=!q;}else if(ch==','&&!q){o.add(c.toString());c.setLength(0);}else c.append(ch);}o.add(c.toString());return o;}
}
