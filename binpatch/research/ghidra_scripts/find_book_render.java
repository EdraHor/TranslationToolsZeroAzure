// find_book_render.java
//
// FUN_1401e5270 (CBookWindow::ConvertMessage) writes the prepared text
// into a buffer at  (param_1 + 0xA0BC). The render function — almost
// certainly a separate one — reads that buffer.
//
// Strategy:
//   1. List callers of FUN_1401e5270 (the convert).
//   2. Within the same module's address neighborhood, find functions
//      that reference offset 0xA0BC (the buffer position) — those are
//      the consumers / renderer.
//   3. Decompile each.
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

public class find_book_render extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_book_render.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Find CBookWindow renderer (consumer of buffer @ +0xA0BC)");
        log("===========================================================");
        log("");

        long convertVA = 0x1401e5270L;
        Listing listing = currentProgram.getListing();

        // ===== task 1: callers of FUN_1401e5270 (convert function) =====
        log("######################################################");
        log("# CALLERS of FUN_1401e5270 (CBookWindow::ConvertMessage)");
        log("######################################################");
        Set<Function> convertCallers = new LinkedHashSet<>();
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
                    if (o instanceof Address && ((Address)o).getOffset() == convertVA) {
                        Function cf = getFunctionContaining(ins.getAddress());
                        String fname = (cf != null) ? cf.getName() + "@" + cf.getEntryPoint() : "(none)";
                        log("  CALL/JMP from " + ins.getAddress() + " in " + fname);
                        if (cf != null) convertCallers.add(cf);
                    }
                }
            }
        }
        log("# Distinct: " + convertCallers.size());
        log("");

        // ===== task 2: any function that uses offset 0xA0BC =====
        // Look for any instruction with operand using +0xA0BC or +0xA0xx range
        // (we use a few common encodings).
        log("######################################################");
        log("# Functions that reference offset 0xA0BC (buffer)");
        log("######################################################");
        Set<Function> bufferUsers = new LinkedHashSet<>();
        Map<Function, List<Address>> bufferSites = new LinkedHashMap<>();

        InstructionIterator it2 = listing.getInstructions(true);
        while (it2.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it2.next();
            // scan operand objects for scalars equal to 0xA0BC
            int nOps = ins.getNumOperands();
            for (int i = 0; i < nOps; i++) {
                Object[] objs = ins.getOpObjects(i);
                if (objs == null) continue;
                for (Object o : objs) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0xA0BCL) {
                            Function cf = getFunctionContaining(ins.getAddress());
                            if (cf != null) {
                                bufferUsers.add(cf);
                                bufferSites.computeIfAbsent(cf, k -> new ArrayList<>()).add(ins.getAddress());
                            }
                        }
                    }
                }
            }
        }
        log("# Distinct: " + bufferUsers.size());
        for (Function fn : bufferUsers) {
            log("  " + fn.getName() + "@" + fn.getEntryPoint() + "  refs=" + bufferSites.get(fn).size());
        }
        log("");

        // ===== decompile combined set =====
        Set<Function> allTargets = new LinkedHashSet<>();
        allTargets.addAll(convertCallers);
        allTargets.addAll(bufferUsers);
        // exclude FUN_1401e5270 itself
        allTargets.removeIf(f -> f.getEntryPoint().getOffset() == convertVA);

        log("######################################################");
        log("# Decompiled — total: " + allTargets.size());
        log("######################################################");
        log("");

        int n = 0;
        for (Function fn : allTargets) {
            n++;
            log("================================================================");
            log("# #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 15) {
                log("(capped at 15)");
                break;
            }
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
