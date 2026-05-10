// find_cmp80_jnc.java
//
// Wider hunt: every CMP <reg8>, 0x80 immediately followed by a JNC /
// JAE / JNB conditional jump (short or near). This catches all variants
// of the "byte >= 0x80 -> skip" gate, regardless of pointer register
// or jump offset.
//
// For each hit, decompile the containing function and dump the exact
// bytes / instructions of the gate so we can plan a per-site patch.
//
//@category TrailsFromZero
//@runtime Java

import java.io.PrintWriter;
import java.io.FileWriter;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_cmp80_jnc extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_cmp80_jnc.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# CMP <reg8>, 0x80  followed by  JNC/JAE/JNB");
        log("===========================================================");
        log("");

        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);
        Map<Function, List<Address>> hits = new LinkedHashMap<>();
        long total = 0;

        Instruction prev = null;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            if (prev != null) {
                if (isCmpReg8With0x80(prev) && isJncJaeJnb(ins)) {
                    Function fn = getFunctionContaining(prev.getAddress());
                    if (fn != null) {
                        hits.computeIfAbsent(fn, k -> new ArrayList<>()).add(prev.getAddress());
                        total++;
                    }
                }
            }
            prev = ins;
        }
        log("Total CMP-then-JNC sites: " + total);
        log("Distinct functions:       " + hits.size());
        log("");

        // List every site
        log("# Sites:");
        for (Map.Entry<Function, List<Address>> e : hits.entrySet()) {
            Function fn = e.getKey();
            for (Address a : e.getValue()) {
                Instruction cmp = listing.getInstructionAt(a);
                Instruction jmp = listing.getInstructionAt(a.add(cmp.getLength()));
                String tag = "";
                if (fn.getEntryPoint().getOffset() == 0x1401ce2b0L) tag = "  (FUN_1401ce2b0 - already patched)";
                log(String.format("  %s   %-15s   %s   in %s%s",
                        a, bytesHex(cmp), bytesHex(jmp),
                        fn.getName() + "@" + fn.getEntryPoint(), tag));
            }
        }
        log("");

        // Decompile each distinct function (skip the known one)
        log("===========================================================");
        log("# Decompiled hit functions (skipping FUN_1401ce2b0)");
        log("===========================================================");
        log("");
        for (Map.Entry<Function, List<Address>> e : hits.entrySet()) {
            Function fn = e.getKey();
            if (fn.getEntryPoint().getOffset() == 0x1401ce2b0L) continue;
            log("================================================================");
            log("# " + fn.getName() + "@" + fn.getEntryPoint() +
                "  (gate sites: " + e.getValue().size() + ")");
            log("================================================================");
            // For each gate site, dump 8-byte before + 14-byte after disassembly
            for (Address a : e.getValue()) {
                log("--- gate @ " + a + " ---");
                int dumped = 0;
                Address cur = a;
                // back up 4 instructions
                Address back = a;
                for (int k = 0; k < 4; k++) {
                    Instruction p = listing.getInstructionBefore(back);
                    if (p == null) break;
                    back = p.getAddress();
                }
                Address dumpAddr = back;
                while (dumpAddr.compareTo(a.add(40)) < 0 && dumped < 20) {
                    Instruction ins = listing.getInstructionAt(dumpAddr);
                    if (ins == null) break;
                    String operandStr = "";
                    int n = ins.getNumOperands();
                    if (n >= 1) operandStr = ins.getDefaultOperandRepresentation(0);
                    if (n >= 2) operandStr += ", " + ins.getDefaultOperandRepresentation(1);
                    log(String.format("    %s   %-18s   %s %s",
                            ins.getAddress().toString(),
                            bytesHex(ins),
                            ins.getMnemonicString(),
                            operandStr));
                    dumpAddr = dumpAddr.add(ins.getLength());
                    dumped++;
                }
                log("");
            }
            log("# Decompilation:");
            log(decompileFn(fn));
            log("");
        }

        log("# DONE");
        out.close();
        println("DONE -> " + outPath);
    }

    boolean isCmpReg8With0x80(Instruction ins) {
        if (!ins.getMnemonicString().equals("CMP")) return false;
        if (ins.getNumOperands() < 2) return false;
        Object[] objs = ins.getOpObjects(1);
        if (objs == null) return false;
        for (Object o : objs) {
            if (o instanceof Scalar) {
                long v = ((Scalar) o).getUnsignedValue();
                if (v == 0x80) {
                    // Make sure operand 0 is an 8-bit register
                    String op0 = ins.getDefaultOperandRepresentation(0).toUpperCase();
                    if (op0.endsWith("L") || op0.endsWith("H") || op0.matches("R\\d+B")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    boolean isJncJaeJnb(Instruction ins) {
        String m = ins.getMnemonicString();
        return m.equals("JNC") || m.equals("JAE") || m.equals("JNB");
    }

    String bytesHex(Instruction ins) {
        try {
            byte[] b = ins.getBytes();
            StringBuilder s = new StringBuilder();
            for (byte x : b) s.append(String.format("%02X ", x & 0xFF));
            return s.toString().trim();
        } catch (Exception e) { return "?"; }
    }
    String bytesHex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02X ", x & 0xFF));
        return s.toString().trim();
    }

    void log(String s) {
        out.println(s);
        if (s.length() < 200) println(s);
    }

    String decompileFn(Function fn) {
        try {
            DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
            if (res != null && res.getDecompiledFunction() != null) {
                String c = res.getDecompiledFunction().getC();
                if (c != null) return c;
            }
        } catch (Exception ex) {
            return "// decompile error: " + ex.getMessage();
        }
        return "// (no decomp result)";
    }
}
