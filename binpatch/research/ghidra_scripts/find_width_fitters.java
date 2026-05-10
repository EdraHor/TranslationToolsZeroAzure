// find_width_fitters.java
//
// Hunt for "width-aware fitter" functions: those that measure text width,
// compare with a UI-cell limit, and either truncate or substitute glyphs
// (e.g., fullwidth->halfwidth katakana conversion typical for JP UIs).
//
// Symptoms we're chasing:
//   - t_town list in battle notebook: long names in halfwidth lose chars,
//     in passthrough text breaks with garbage tail "K[block][bytes]".
//   - t_memo (passthrough): long names get squeezed but two strings get
//     interleaved — "Искусства/Прострт|скуссива/Мираж".
//   - t_ittxt (food/fish) works fine — different code path.
//
// Strategy:
//   PASS A: callers of FUN_140216720 (width calculator) — UI consumers.
//   PASS B: callers of FUN_14028b700 (already-patched P3 truncator) +
//           callers of FUN_1402873c0 (notebook formatter) — sibling paths.
//   PASS C: functions with both "byte read loop" AND "table lookup"
//           (CALL <addr>; MOV <reg>, byte ptr [base + idx*scale]) —
//           classic SJIS<->halfwidth converter pattern.
//   PASS D: functions that store ".." OR halfwidth dot 0xA1/0xA5 inline
//           AND have a separate width-call branch.
//
// Output: out_width_fitters.txt with caller table and decompiled top-N.
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
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_width_fitters extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    // Known anchor functions (verified halfwidth-aware OR already patched)
    static final long F_WIDTH_CALC      = 0x140216720L; // width calculator
    static final long F_P3_TRUNC        = 0x14028b700L; // quest preview truncate (P3 patched)
    static final long F_NOTEBOOK_FMT    = 0x1402873c0L; // notebook text formatter
    static final long F_MSG_FMT         = 0x140332ba0L; // message text formatter
    static final long F_BOOK_CONVERT    = 0x1401e5270L; // CBookWindow::ConvertMessage

    static final Set<Long> KNOWN_OK = new HashSet<>(Arrays.asList(
        F_WIDTH_CALC, F_NOTEBOOK_FMT, F_MSG_FMT, F_BOOK_CONVERT,
        0x140212f40L, 0x140215400L, 0x14020e6b0L, 0x140215190L,
        0x140078850L, 0x140078d00L, 0x140078fb0L, 0x140079360L,
        0x1401ce2b0L  // P2-patched
        // F_P3_TRUNC NOT in this list — we want its callers
    ));

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_width_fitters.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Width-aware fitter hunt (t_town list breakage)");
        log("===========================================================");
        log("");

        Map<Long, Candidate> candidates = new LinkedHashMap<>();

        // ============ PASS A: callers of FUN_140216720 ============
        log("############################################################");
        log("# PASS A: callers of FUN_140216720 (width calculator)");
        log("############################################################");
        log("");
        addCallers(F_WIDTH_CALC, candidates, "uses_width_calc");

        // ============ PASS B: callers of P3 + notebook formatter + msg formatter ============
        log("############################################################");
        log("# PASS B: callers of known truncate/formatter functions");
        log("############################################################");
        log("");
        addCallers(F_P3_TRUNC,     candidates, "calls_P3_trunc");
        addCallers(F_NOTEBOOK_FMT, candidates, "calls_notebook_fmt");
        addCallers(F_MSG_FMT,      candidates, "calls_msg_fmt");
        addCallers(F_BOOK_CONVERT, candidates, "calls_book_convert");

        // ============ PASS C: classify candidates by inner pattern ============
        log("############################################################");
        log("# PASS C: classification (byte-loop, table-lookup, halfwidth)");
        log("############################################################");
        log("");

        for (Candidate c : candidates.values()) {
            classify(c);
        }

        // ============ Output table ============
        List<Candidate> sorted = new ArrayList<>(candidates.values());
        sorted.sort((a, b) -> Integer.compare(b.score(), a.score()));

        log(String.format("%-22s %5s %5s %5s %5s %5s %5s %5s   %s",
            "function", "byteR", "tblL", "wCAL", "wCMP", "trunc", "subst", "hwAW", "tags"));
        for (Candidate c : sorted) {
            log(String.format("%-22s %5d %5d %5d %5d %5d %5d %5d   %s",
                "FUN_" + Long.toHexString(c.entry),
                c.byteReadLoops, c.tableLookups, c.widthCalls, c.widthCmps,
                c.truncMarkers, c.substWrites, c.halfwidthAware ? 1 : 0,
                String.join(",", c.tags)));
        }
        log("");
        log("# Total candidates: " + sorted.size());
        log("");

        // ============ Decompile top candidates ============
        log("############################################################");
        log("# Decompiled — top scored candidates that are NOT halfwidth-aware");
        log("# (these are the most likely culprits)");
        log("############################################################");
        log("");

        int decompiled = 0;
        for (Candidate c : sorted) {
            if (decompiled >= 12) break;
            if (c.halfwidthAware) continue;
            if (KNOWN_OK.contains(c.entry)) continue;
            if (c.score() < 2) continue;

            log("================================================================");
            log("# FUN_" + Long.toHexString(c.entry) +
                "  score=" + c.score() +
                "  tags=[" + String.join(",", c.tags) + "]");
            log("================================================================");
            log("");
            String dec = decompile(c.entry);
            log(dec);
            log("");
            decompiled++;
        }

        log("");
        log("# DONE");
        out.flush();
        out.close();
        println("Wrote " + outPath);
    }

    // ---------- helpers ----------

    static class Candidate {
        long entry;
        Set<String> tags = new LinkedHashSet<>();
        int byteReadLoops;   // MOVZX <reg>, byte ptr [<reg>] count
        int tableLookups;    // MOV <reg>, byte ptr [<reg>+<reg>*] (indexed)
        int widthCalls;      // CALL FUN_140216720
        int widthCmps;       // CMP <reg>, <small immediate> after width call
        int truncMarkers;    // MOV byte ptr, 0x2E (dot)
        int substWrites;     // MOV byte ptr, <reg> (string output writes)
        boolean halfwidthAware;

        int score() {
            int s = 0;
            if (byteReadLoops > 0) s += 1;
            if (tableLookups   > 0) s += 1;
            if (widthCalls     > 0) s += 2;
            if (widthCmps      > 0) s += 1;
            if (truncMarkers   > 0) s += 1;
            if (substWrites    > 1) s += 1;
            if (halfwidthAware    ) s -= 5;  // strong negative
            return s;
        }
    }

    void addCallers(long calleeAddr, Map<Long, Candidate> dst, String tag) {
        Address a = toAddr(calleeAddr);
        Function callee = getFunctionAt(a);
        if (callee == null) {
            log("  [WARN] no function at " + Long.toHexString(calleeAddr));
            return;
        }
        Set<Function> callers = callee.getCallingFunctions(monitor);
        log("  " + callee.getName() + " has " + callers.size() + " callers (tag=" + tag + ")");
        int added = 0;
        for (Function f : callers) {
            long e = f.getEntryPoint().getOffset();
            if (KNOWN_OK.contains(e)) continue;
            Candidate c = dst.computeIfAbsent(e, k -> {
                Candidate x = new Candidate();
                x.entry = e;
                return x;
            });
            c.tags.add(tag);
            added++;
        }
        log("  → added " + added + " new candidates");
        log("");
    }

    void classify(Candidate c) {
        Function f = getFunctionAt(toAddr(c.entry));
        if (f == null) return;
        AddressSetView body = f.getBody();
        InstructionIterator it = currentProgram.getListing().getInstructions(body, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String mnem = ins.getMnemonicString();
            String full = ins.toString();

            // byte read loop
            if ((mnem.equals("MOVZX") || mnem.equals("MOV")) &&
                full.contains("byte ptr [") && !full.contains("*")) {
                c.byteReadLoops++;
            }
            // indexed table lookup
            if (mnem.equals("MOV") && full.contains("byte ptr [") && full.contains("*")) {
                c.tableLookups++;
            }
            // CALL to width calc
            if (mnem.equals("CALL")) {
                Reference[] refs = ins.getReferencesFrom();
                for (Reference r : refs) {
                    if (r.getReferenceType().isCall()) {
                        long tgt = r.getToAddress().getOffset();
                        if (tgt == F_WIDTH_CALC) c.widthCalls++;
                    }
                }
            }
            // CMP <reg>, <small imm>  — width comparison
            if (mnem.equals("CMP")) {
                Object[] ops = ins.getOpObjects(1);
                for (Object o : ops) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v >= 0x10 && v <= 0x400) c.widthCmps++;
                    }
                }
            }
            // truncate marker write
            if (mnem.equals("MOV") && full.contains("byte ptr [")) {
                Object[] ops = ins.getOpObjects(1);
                for (Object o : ops) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x2E || v == 0xA1 || v == 0xA5) c.truncMarkers++;
                    }
                }
            }
            // substring/copy writes
            if (mnem.equals("MOV") && full.contains("byte ptr [") &&
                ins.getNumOperands() == 2) {
                String op1 = ins.getDefaultOperandRepresentation(1);
                if (op1.matches("[A-Z]+L?") || op1.matches("R[0-9]+B")) {
                    c.substWrites++;
                }
            }
            // halfwidth-aware: LEA <reg>, [<reg>+0x60] / SUB +0x60 / ADD +0x60
            if ((mnem.equals("LEA") || mnem.equals("SUB") || mnem.equals("ADD")) &&
                (full.contains("0x60") || full.contains("0x5f") || full.contains("0x5F"))) {
                c.halfwidthAware = true;
            }
            // halfwidth-aware: CMP <reg>, 0x40 (paired with shift trick)
            if (mnem.equals("CMP")) {
                Object[] ops = ins.getOpObjects(1);
                for (Object o : ops) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x40) {
                            // not strong on its own, but paired with shift+0x60 it's the pattern
                        }
                    }
                }
            }
        }
    }

    String decompile(long addr) {
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) return "  [no function]";
        DecompileResults r = decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());
        if (r == null || !r.decompileCompleted()) return "  [decompile failed]";
        return r.getDecompiledFunction().getC();
    }

    void log(String s) {
        out.println(s);
        println(s);
    }
}
