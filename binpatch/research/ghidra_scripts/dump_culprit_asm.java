// dump_culprit_asm.java
//
// Final pre-patch step: dump exact x86-64 instructions of FUN_1401ce2b0
// (the suspected item-description renderer that loops forever on
// halfwidth bytes), and list all its callers.
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

public class dump_culprit_asm extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_culprit_asm.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        long target = 0x1401ce2b0L;
        Address aa = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
        Function fn = getFunctionAt(aa);

        log("================================================================");
        log("# ASM DUMP — " + (fn != null ? fn.getName() : "(none)") + " @ 0x" + Long.toHexString(target));
        log("# body: " + fn.getBody().getMinAddress() + " .. " + fn.getBody().getMaxAddress() +
            "  size=" + fn.getBody().getNumAddresses() + " bytes");
        log("================================================================");

        Listing listing = currentProgram.getListing();
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
            log(String.format("  %s   %-22s   %s %s",
                    ins.getAddress().toString(),
                    hex.toString().trim(),
                    ins.getMnemonicString(),
                    operandStr));
        }
        log("");

        // ------ callers ------
        log("################################################################");
        log("# CALLERS of " + fn.getName() + "  (who renders item descriptions?)");
        log("################################################################");
        Set<Function> callerFns = new LinkedHashSet<>();
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
                    if (o instanceof Address && ((Address) o).getOffset() == target) {
                        Function cf = getFunctionContaining(ins.getAddress());
                        String fname = (cf != null) ? cf.getName() + "@" + cf.getEntryPoint() : "(none)";
                        log("  CALL/JMP from " + ins.getAddress() + " in " + fname);
                        if (cf != null) callerFns.add(cf);
                    }
                }
            }
        }
        log("# Distinct caller functions: " + callerFns.size());
        log("");

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
