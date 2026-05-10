// find_utf8_validator_callers.java
//
// Goal: confirm the UTF-8 validators FUN_1400c3c70 / FUN_1400c4540 as the
// origin of the tooltip-path string truncation, and prepare the binary
// patch.
//
// Outputs:
//   1. All callers of FUN_1400c3c70 (decompiled).
//   2. All callers of FUN_1400c4540 (decompiled).
//   3. For each validator, the exact asm address + hex bytes of every
//      CMP ?, 0xC0 instruction (this is the byte to flip in the patch).
//   4. Same for any CMP ?, 0x80 (UTF-8 ASCII boundary check), to map
//      out the surrounding logic.
//
//@category TrailsFromZero
//@menupath Tools.Misc.find_utf8_validator_callers
//@runtime Java

import java.io.PrintWriter;
import java.io.FileWriter;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_utf8_validator_callers extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_utf8_validator.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("=========================================================");
        log("# UTF-8 validator analysis: FUN_1400c3c70 + FUN_1400c4540");
        log("# Image base: " + currentProgram.getImageBase());
        log("=========================================================");
        log("");

        long[] validators = { 0x1400c3c70L, 0x1400c4540L };

        for (long va : validators) {
            Address vaddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
            Function fn = getFunctionAt(vaddr);
            if (fn == null) {
                log("# NO FUNCTION AT " + Long.toHexString(va));
                continue;
            }

            log("################################################################");
            log("# VALIDATOR: " + fn.getName() + " @ " + fn.getEntryPoint());
            log("# Body: " + fn.getBody().getMinAddress() + " .. " + fn.getBody().getMaxAddress());
            log("################################################################");
            log("");

            // ---- (1) Find all CMP ?, 0xC0  and  CMP ?, 0x80  inside the function ----
            log("## Magic-byte CMP/SUB instructions (PATCH SITES):");
            int[] patchTargets = { 0x80, 0xA0, 0xA1, 0xC0, 0xDF, 0xE0, 0xF0, 0xF8, 0xFC };
            Listing listing = currentProgram.getListing();
            AddressSetView body = fn.getBody();
            for (Address a : body.getAddresses(true)) {
                Instruction ins = listing.getInstructionAt(a);
                if (ins == null) continue;
                String mnem = ins.getMnemonicString();
                if (!mnem.equals("CMP") && !mnem.equals("SUB") && !mnem.equals("AND")) continue;
                int nOps = ins.getNumOperands();
                for (int i = 0; i < nOps; i++) {
                    Object[] objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            for (int t : patchTargets) {
                                if (v == t) {
                                    // print: address, full instr text, hex bytes
                                    StringBuilder hex = new StringBuilder();
                                    try {
                                        byte[] bytes = ins.getBytes();
                                        for (byte b : bytes) hex.append(String.format("%02X ", b & 0xFF));
                                    } catch (Exception e) {}
                                    log(String.format("  %s   %-30s  %s   bytes=[%s]",
                                            ins.getAddress().toString(),
                                            mnem + " " + ins.getDefaultOperandRepresentation(0)
                                                + ", " + ins.getDefaultOperandRepresentation(1),
                                            String.format("(magic 0x%02X)", t),
                                            hex.toString().trim()));
                                }
                            }
                        }
                    }
                }
            }
            log("");

            // ---- (2) callers ----
            log("## Callers of " + fn.getName() + ":");
            Set<Function> callers = fn.getCallingFunctions(monitor);
            for (Function c : callers) {
                log("  " + c.getName() + " @ " + c.getEntryPoint() +
                    "   size=" + c.getBody().getNumAddresses());
            }
            log("# Total callers: " + callers.size());
            log("");

            // ---- (3) decompile each caller ----
            log("## Decompiled callers (capped at 8):");
            int n = 0;
            for (Function c : callers) {
                n++;
                log("================================================================");
                log("# Caller of " + fn.getName() + ": " + c.getName() + " @ " + c.getEntryPoint());
                log("================================================================");
                log(decompileFn(c));
                log("");
                if (n >= 8) {
                    log("(capped at 8 callers)");
                    break;
                }
            }
            log("");
        }

        log("# DONE");
        out.close();
        println("DONE -> " + outPath);
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
