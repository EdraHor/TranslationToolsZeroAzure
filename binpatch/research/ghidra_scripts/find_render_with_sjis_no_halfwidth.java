// find_render_with_sjis_no_halfwidth.java
//
// Find text *render* functions that:
//   - have ASCII gate (CMP byte,0x80 OR TEST byte; JS OR CMP byte,0x7F)
//   - have SJIS pair gate (CMP with 0x81 / 0x9F / 0xE0 / 0xFC)
//   - have NO halfwidth-zone handling (no CMP with 0xA0 / 0xA1 / 0xC0 / 0xDF / 0xDE)
//   - have NO halfwidth shift trick (no LEA reg, [reg + 0x60 / 0x5F])
//
// Renders DON'T need byte_stores: they often pass the byte as parameter
// to a draw_glyph function. Hence we drop the stores filter.
//
// Also dump:
//   - FUN_1402738c0 (called from CBookWindow::SetMessage right after Convert)
//   - FUN_140212f40 (CMessageWindow render — known halfwidth-aware, for comparison)
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

public class find_render_with_sjis_no_halfwidth extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_render_no_hw.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Render candidates: ASCII gate + SJIS pair gate + NO halfwidth");
        log("===========================================================");
        log("");

        // Per-function stats:
        //   [0] ASCII gate: CMP byte,0x80 OR TEST+JS OR CMP byte,0x7F
        //   [1] SJIS pair gate: CMP byte,0x81 / 0x9F / 0xE0 / 0xFC
        //   [2] halfwidth CMP: 0xA0 / 0xA1 / 0xC0 / 0xDE / 0xDF
        //   [3] halfwidth shift: LEA reg,[reg+0x60] / [reg+0x5F]
        //   [4] byte stores
        //   [5] CALL count (rendering = lots of calls to draw_glyph)
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
            int[] s = stats.computeIfAbsent(fn, k -> new int[6]);
            String mnem = ins.getMnemonicString();

            // CMP <r8>, imm
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
                        }
                    }
                }
            }
            // TEST r8,r8 ; JS  → ASCII gate
            if (prev != null && prev.getMnemonicString().equals("TEST") && mnem.equals("JS")) {
                String op0 = prev.getDefaultOperandRepresentation(0).toUpperCase();
                String op1 = prev.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.equals(op1) && (op0.endsWith("L") || op0.matches("R\\d+B"))) {
                    s[0]++;
                }
            }
            // LEA reg, [reg + 0x60 / 0x5F] — halfwidth shift
            if (mnem.equals("LEA") && ins.getNumOperands() >= 2) {
                Object[] o1 = ins.getOpObjects(1);
                if (o1 != null) for (Object o : o1) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x60 || v == 0x5F) s[3]++;
                    }
                }
            }
            // ADD/SUB reg, 0x60 / 0x5F — halfwidth shift via ADD
            if ((mnem.equals("ADD") || mnem.equals("SUB")) && ins.getNumOperands() >= 2) {
                Object[] o1 = ins.getOpObjects(1);
                if (o1 != null) for (Object o : o1) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x60 || v == 0x5F) s[3]++;
                    }
                }
            }
            // MOV [reg], r8 — byte store
            if (mnem.equals("MOV") && ins.getNumOperands() >= 2) {
                String op0 = ins.getDefaultOperandRepresentation(0);
                String op1 = ins.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.startsWith("byte ptr") && (op1.endsWith("L") || op1.matches("R\\d+B"))) {
                    s[4]++;
                }
            }
            // CALL — render funcs have many calls
            if (mnem.equals("CALL")) s[5]++;
            prev = ins;
        }
        log("Scanned " + ic + " instructions across " + stats.size() + " functions.");
        log("");

        // Filter: ascii_gate>0 AND sjis_pair_gate>0 AND halfwidth_cmps==0 AND lea_60==0
        log("############################################################");
        log("# Filter: ascii_gate>0 AND sjis_pair_gate>0 AND no_halfwidth AND no_shift");
        log("############################################################");
        log("");

        List<Function> candidates = new ArrayList<>();
        for (Map.Entry<Function, int[]> e : stats.entrySet()) {
            int[] s = e.getValue();
            if (s[0] == 0) continue;     // need ASCII gate
            if (s[1] == 0) continue;     // need SJIS pair gate
            if (s[2] > 0) continue;      // skip halfwidth-aware
            if (s[3] > 0) continue;      // skip shift-trick
            candidates.add(e.getKey());
        }

        // Sort by combined signal: ASCII + SJIS pair + CALLS (renders have many calls)
        candidates.sort((a, b) -> {
            int[] sa = stats.get(a); int[] sb = stats.get(b);
            int wa = sa[0] * 3 + sa[1] * 3 + sa[5];
            int wb = sb[0] * 3 + sb[1] * 3 + sb[5];
            return wb - wa;
        });

        log(String.format("%-38s  %s", "function", "ASCII SJIS HW SHIFT STORES CALLS"));
        for (Function fn : candidates) {
            int[] s = stats.get(fn);
            log(String.format("%-38s  %5d %4d %2d %5d %6d %5d",
                fn.getName() + "@" + fn.getEntryPoint(),
                s[0], s[1], s[2], s[3], s[4], s[5]));
        }
        log("");
        log("# Total candidates: " + candidates.size());
        log("");

        // Decompile top 8 candidates
        log("############################################################");
        log("# Decompiled top 8 candidates");
        log("############################################################");
        log("");
        int n = 0;
        for (Function fn : candidates) {
            n++;
            int[] s = stats.get(fn);
            log("================================================================");
            log("# #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                "  ASCII=" + s[0] + " SJIS=" + s[1] + " STORES=" + s[4] + " CALLS=" + s[5]);
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 8) {
                log("(capped at 8)");
                break;
            }
        }

        // ALSO dump specific suspects:
        //   FUN_1402738c0 — called from CBookWindow::SetMessage
        //   FUN_140212f40 — known CMessageWindow render (halfwidth-aware)
        //   FUN_140215210 — was in interesting CMessageWindow region
        //   FUN_14032e7b0 — quest UI region
        log("############################################################");
        log("# Targeted dumps");
        log("############################################################");
        log("");

        long[] targets = {
            0x1402738c0L,  // called from SetMessage right after Convert
            0x140212f40L,  // CMessageWindow render (for halfwidth pattern reference)
            0x140215210L,  // CMessageWindow region candidate
            0x14032e7b0L,  // quest UI region candidate
            0x140268050L,  // earlier suspect
            0x140215190L,  // earlier suspect
        };
        for (long ea : targets) {
            Function fn = getFunctionAt(toAddr(ea));
            if (fn == null) {
                log("# (no function at " + Long.toHexString(ea) + ")");
                continue;
            }
            int[] s = stats.get(fn);
            log("================================================================");
            log("# Target: " + fn.getName() + "@" + fn.getEntryPoint() +
                (s != null ? "  ASCII=" + s[0] + " SJIS=" + s[1] + " HW=" + s[2] +
                             " SHIFT=" + s[3] + " STORES=" + s[4] + " CALLS=" + s[5]
                           : ""));
            log("================================================================");
            log(decompileFn(fn));
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
