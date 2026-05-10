// dump_book_module.java
//
// List every function in 0x1401e0000..0x1401f0000 (the book/window
// module containing CBookWindow::ConvertMessage / SetMessage). For
// each, print size + count of CMP/JNC/JS magic-byte instructions.
// We're looking for the render function — it should:
//   - be in this module
//   - have substantial size (> 200 bytes)
//   - contain text-loop signatures (CMP byte, 0x80, JNC; reads
//     pointers at offset 0x90/0x98 of param_1)
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

public class dump_book_module extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_book_module.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Book/Window module — functions in 0x1401e0000..0x1401f0000");
        log("===========================================================");
        log("");

        Listing listing = currentProgram.getListing();

        // Per-function stats: cmp80 count, JNC count, INC RDI/etc count
        Map<Function, int[]> stats = new HashMap<>();
        // [0]=CMP r8,0x80, [1]=JNC, [2]=cmp halfwidth (any 0xA1/0xC0/0xDF/0xE0), [3]=*(p+0x90) read, [4]=*(p+0x98) read, [5]=byte stores

        FunctionIterator fnIt = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> regionFns = new ArrayList<>();
        while (fnIt.hasNext()) {
            Function fn = fnIt.next();
            long ea = fn.getEntryPoint().getOffset();
            if (ea < 0x1401e0000L || ea > 0x1401f0000L) continue;
            regionFns.add(fn);
            stats.put(fn, new int[6]);
        }
        log("# Functions in module: " + regionFns.size());
        log("");

        // Walk every instruction in module range, collect stats
        for (Function fn : regionFns) {
            int[] s = stats.get(fn);
            for (Address a : fn.getBody().getAddresses(true)) {
                Instruction ins = listing.getInstructionAt(a);
                if (ins == null) continue;
                String mnem = ins.getMnemonicString();

                // CMP <r8>, 0x80
                if (mnem.equals("CMP") && ins.getNumOperands() >= 2) {
                    Object[] objs = ins.getOpObjects(1);
                    String op0 = ins.getDefaultOperandRepresentation(0).toUpperCase();
                    if (objs != null && (op0.endsWith("L") || op0.matches("R\\d+B"))) {
                        for (Object o : objs) {
                            if (o instanceof Scalar) {
                                long v = ((Scalar)o).getUnsignedValue();
                                if (v == 0x80) s[0]++;
                                if (v == 0xA0 || v == 0xA1 || v == 0xC0 || v == 0xDF || v == 0xE0) s[2]++;
                            }
                        }
                    }
                }
                // JNC/JNB/JAE
                if (mnem.equals("JNC") || mnem.equals("JNB") || mnem.equals("JAE")) s[1]++;
            }
        }

        // Print summary table
        log(String.format("%-35s  %5s  %5s  %5s  %s",
            "function@addr", "size", "CMP80", "JNC", "halfwidth_cmps"));
        for (Function fn : regionFns) {
            int[] s = stats.get(fn);
            log(String.format("%-35s  %5d  %5d  %5d  %5d",
                fn.getName() + "@" + fn.getEntryPoint(),
                (int)fn.getBody().getNumAddresses(),
                s[0], s[1], s[2]));
        }
        log("");

        // Print any function with CMP80 > 0 and CMP_halfwidth == 0 — those are
        // candidates for the buggy render (no halfwidth path).
        log("############################################################");
        log("# Candidates: CMP80 > 0 AND no halfwidth CMP (potential bug)");
        log("############################################################");
        log("");
        List<Function> candidates = new ArrayList<>();
        for (Function fn : regionFns) {
            int[] s = stats.get(fn);
            if (s[0] > 0 && s[2] == 0) {
                candidates.add(fn);
                log("  " + fn.getName() + "@" + fn.getEntryPoint() +
                    "  CMP80=" + s[0] + " JNC=" + s[1]);
            }
        }
        log("");
        log("# Total candidates: " + candidates.size());
        log("");

        // Decompile candidates
        log("############################################################");
        log("# Decompiled candidates");
        log("############################################################");
        log("");
        int n = 0;
        for (Function fn : candidates) {
            n++;
            log("================================================================");
            log("# Candidate #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 10) {
                log("(capped at 10)");
                break;
            }
        }

        // Also dump the largest function in the module (if not yet covered)
        log("############################################################");
        log("# Largest functions in module (skipping known small ones)");
        log("############################################################");
        log("");
        regionFns.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
        n = 0;
        for (Function fn : regionFns) {
            int sz = (int)fn.getBody().getNumAddresses();
            if (sz < 200) break;
            // skip already-known and already decompiled candidates
            long ea = fn.getEntryPoint().getOffset();
            if (ea == 0x1401e5270L || ea == 0x1401e60d0L) continue;
            if (candidates.contains(fn)) continue;
            n++;
            log("================================================================");
            log("# Large fn #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                "   size=" + sz);
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 6) break;
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
