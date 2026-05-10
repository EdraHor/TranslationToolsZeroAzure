// dump_utf8_decoder_asm.java
//
// Final pre-patch diagnostic:
//   1) Dump the exact x86-64 instructions at the start of FUN_1400794a0
//      (UTF-8 byte parser) so we know which bytes to flip.
//   2) Find ALL callers of FUN_140079360 (UTF-8 -> wchar buffer decoder).
//      If those callers include item-description / book / memo / quest
//      rendering paths, patching FUN_1400794a0 will fix the tooltip bug.
//   3) Same for FUN_140078090 (the SJIS-path renderer used when detector
//      returns 0/1/2) — if descriptions go through it, the bug is
//      somewhere else.
//
//@category TrailsFromZero
//@menupath Tools.Misc.dump_utf8_decoder_asm
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

public class dump_utf8_decoder_asm extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_utf8_decoder_asm.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Final pre-patch diagnostic");
        log("===========================================================");
        log("");

        // ---- (1) full asm dump for FUN_1400794a0 (the patch target!)
        long[] dumpFns = { 0x1400794a0L, 0x140079360L };
        for (long ea : dumpFns) {
            Address aa = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ea);
            Function fn = getFunctionAt(aa);
            log("################################################################");
            log("# ASM DUMP — " + (fn != null ? fn.getName() : "(none)") + " @ 0x" + Long.toHexString(ea));
            log("################################################################");
            if (fn == null) { log("# NOT A FUNCTION!"); continue; }

            Listing listing = currentProgram.getListing();
            int idx = 0;
            for (Address a : fn.getBody().getAddresses(true)) {
                Instruction ins = listing.getInstructionAt(a);
                if (ins == null) continue;
                StringBuilder hex = new StringBuilder();
                try {
                    byte[] bytes = ins.getBytes();
                    for (byte b : bytes) hex.append(String.format("%02X ", b & 0xFF));
                } catch (Exception e) {}
                String operandStr = "";
                int n = ins.getNumOperands();
                if (n >= 1) operandStr = ins.getDefaultOperandRepresentation(0);
                if (n >= 2) operandStr += ", " + ins.getDefaultOperandRepresentation(1);
                log(String.format("  %s   %-15s   %s %s",
                        ins.getAddress().toString(),
                        hex.toString().trim(),
                        ins.getMnemonicString(),
                        operandStr));
                idx++;
                // Cap at first 100 instructions per function (we only need start)
                if (idx >= (ea == 0x1400794a0L ? 80 : 60)) {
                    log("  ... (truncated)");
                    break;
                }
            }
            log("");
        }

        // ---- (2) callers of FUN_140079360 (UTF-8 decoder loop)
        long[] inv = { 0x140079360L, 0x140078090L, 0x140078fb0L,
                       0x140077580L, 0x1400772c0L, 0x1400776a0L };
        for (long t : inv) {
            scanCallers(t);
        }

        log("# DONE");
        out.close();
        println("DONE -> " + outPath);
    }

    void scanCallers(long target) throws Exception {
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
        Function fn = getFunctionAt(addr);
        log("################################################################");
        log("# CALLERS of " + (fn != null ? fn.getName() : "(none)") + " @ 0x" + Long.toHexString(target));
        log("################################################################");
        if (fn == null) { log("# NOT A FUNCTION ENTRY!"); log(""); return; }

        Set<Function> callerFns = new LinkedHashSet<>();
        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            String mnem = ins.getMnemonicString();
            if (!mnem.equals("CALL") && !mnem.equals("JMP")) continue;
            int nOps = ins.getNumOperands();
            for (int i = 0; i < nOps; i++) {
                Object[] objs = ins.getOpObjects(i);
                if (objs == null) continue;
                for (Object o : objs) {
                    if (o instanceof Address) {
                        long ta = ((Address) o).getOffset();
                        if (ta == target) {
                            Function cf = getFunctionContaining(ins.getAddress());
                            String fname = (cf != null) ? cf.getName() + "@" + cf.getEntryPoint() : "(none)";
                            log("  CALL/JMP from " + ins.getAddress() + " in " + fname);
                            if (cf != null) callerFns.add(cf);
                        }
                    }
                }
            }
        }
        log("# Distinct caller functions: " + callerFns.size());
        log("");

        // Decompile up to 8 callers
        int n = 0;
        for (Function cf : callerFns) {
            n++;
            log("--------------------------------------------------------");
            log("# Caller #" + n + ": " + cf.getName() + "@" + cf.getEntryPoint());
            log("--------------------------------------------------------");
            log(decompileFn(cf));
            log("");
            if (n >= 8) break;
        }
        log("");
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
