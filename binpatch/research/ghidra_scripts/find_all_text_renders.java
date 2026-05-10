// find_all_text_renders.java
//
// BROADER scan: list ALL functions that look like text-render loops
// (ASCII gate + SJIS pair gate). Don't filter on halfwidth presence —
// just rank and decompile, so we can spot the buggy render manually.
//
// Halfwidth handling can use a non-obvious pattern:
//   LEA r8,[r8+0x60] ; CMP r8,0x40   (the FUN_140212f40 style)
// or
//   ADD r8,0x60 ; CMP r8,0x40
// Both have the literal 0x60 in LEA/ADD AND 0x40 in CMP.
// So we count both signals as "halfwidth-aware".
//
//@category TrailsFromZero
//@runtime Java

import java.io.PrintWriter;
import java.io.FileWriter;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_all_text_renders extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_all_text_renders.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# ALL text render loops (ASCII gate + SJIS pair gate)");
        log("===========================================================");
        log("");

        // Per-function stats:
        //   [0] ASCII gate
        //   [1] SJIS pair gate (CMP 0x81/0x9F/0xE0/0xFC)
        //   [2] halfwidth direct CMP (0xA0/0xA1/0xC0/0xDE/0xDF)
        //   [3] LEA/ADD/SUB +0x60 / +0x5F (halfwidth shift trick)
        //   [4] CMP <r8>, 0x40 (paired with above for halfwidth zone width)
        //   [5] byte stores
        //   [6] CALL count
        //   [7] CMP 0x9F, 0xE0 separately (SJIS lead pair endpoints)
        Map<Function, int[]> stats = new HashMap<>();

        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);
        Instruction prev = null;
        long ic = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            ic++;
            Function fn = getFunctionContaining(ins.getAddress());
            if (fn == null) { prev = ins; continue; }
            int[] s = stats.computeIfAbsent(fn, k -> new int[8]);
            String mnem = ins.getMnemonicString();

            if (mnem.equals("CMP") && ins.getNumOperands() >= 2) {
                String op0 = ins.getDefaultOperandRepresentation(0).toUpperCase();
                if (op0.endsWith("L") || op0.matches("R\\d+B")) {
                    Object[] o1 = ins.getOpObjects(1);
                    if (o1 != null) for (Object o : o1) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            if (v == 0x80 || v == 0x7F) s[0]++;
                            if (v == 0x81 || v == 0x9F || v == 0xE0 || v == 0xFC) s[1]++;
                            if (v == 0xA0 || v == 0xA1 || v == 0xC0 || v == 0xDE || v == 0xDF) s[2]++;
                            if (v == 0x40) s[4]++;
                            if (v == 0x9F || v == 0xE0) s[7]++;
                        }
                    }
                }
            }
            if (prev != null && prev.getMnemonicString().equals("TEST") && mnem.equals("JS")) {
                String op0 = prev.getDefaultOperandRepresentation(0).toUpperCase();
                String op1 = prev.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.equals(op1) && (op0.endsWith("L") || op0.matches("R\\d+B"))) {
                    s[0]++;
                }
            }
            if ((mnem.equals("LEA") || mnem.equals("ADD") || mnem.equals("SUB")) &&
                ins.getNumOperands() >= 2) {
                Object[] o1 = ins.getOpObjects(1);
                if (o1 != null) for (Object o : o1) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x60 || v == 0x5F) s[3]++;
                    }
                }
            }
            if (mnem.equals("MOV") && ins.getNumOperands() >= 2) {
                String op0 = ins.getDefaultOperandRepresentation(0);
                String op1 = ins.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.startsWith("byte ptr") && (op1.endsWith("L") || op1.matches("R\\d+B"))) {
                    s[5]++;
                }
            }
            if (mnem.equals("CALL")) s[6]++;
            prev = ins;
        }
        log("Scanned " + ic + " instructions across " + stats.size() + " functions.");
        log("");

        // Filter: ASCII gate >= 1 AND SJIS pair gate >= 1
        List<Function> candidates = new ArrayList<>();
        for (Map.Entry<Function, int[]> e : stats.entrySet()) {
            int[] s = e.getValue();
            if (s[0] == 0 || s[1] == 0) continue;
            // halfwidth-aware = direct CMP 0xA0/etc OR (shift +0x60 paired)
            // We compute hw_aware = s[2] + s[3] (rough)
            candidates.add(e.getKey());
        }

        // Sort by combined signal
        candidates.sort((a, b) -> {
            int[] sa = stats.get(a); int[] sb = stats.get(b);
            int wa = sa[0] * 2 + sa[1] * 3 + sa[6] / 5 + sa[5];
            int wb = sb[0] * 2 + sb[1] * 3 + sb[6] / 5 + sb[5];
            return wb - wa;
        });

        log("############################################################");
        log("# All text-render candidates (ASCII gate>0 AND SJIS pair>0)");
        log("# HW = direct halfwidth CMP, SHIFT = LEA/ADD/SUB +0x60/+0x5F");
        log("# CMP40 = CMP byte,0x40 (often paired with shift for halfwidth)");
        log("############################################################");
        log("");
        log(String.format("%-38s  %s", "function", "ASCII SJIS HW SHIFT CMP40 STORES CALLS"));
        for (Function fn : candidates) {
            int[] s = stats.get(fn);
            String hwTag = "";
            if (s[2] > 0) hwTag = " HW_DIRECT";
            else if (s[3] > 0 && s[4] > 0) hwTag = " HW_SHIFT";
            else if (s[5] == 0 && s[6] > 5) hwTag = " ?NO_STORE_BIG";
            else hwTag = " !NO_HW";
            log(String.format("%-38s  %5d %4d %2d %5d %5d %6d %5d%s",
                fn.getName() + "@" + fn.getEntryPoint(),
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], hwTag));
        }
        log("");
        log("# Total candidates: " + candidates.size());
        log("");

        // Decompile only those marked NO_HW (no halfwidth handling at all)
        log("############################################################");
        log("# Decompiled — only candidates WITHOUT any halfwidth signal");
        log("# (HW_direct == 0 AND (SHIFT == 0 OR CMP40 == 0))");
        log("############################################################");
        log("");
        int n = 0;
        for (Function fn : candidates) {
            int[] s = stats.get(fn);
            if (s[2] > 0) continue;                    // direct halfwidth CMP - aware
            if (s[3] > 0 && s[4] > 0) continue;        // shift+CMP40 paired - aware
            n++;
            log("================================================================");
            log("# #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                "  ASCII=" + s[0] + " SJIS=" + s[1] + " HW=" + s[2] +
                " SHIFT=" + s[3] + " CMP40=" + s[4] +
                " STORES=" + s[5] + " CALLS=" + s[6]);
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
