// find_town_pipeline.java
//
// Targeted hunt: find functions that read t_town._dt and t_memo._dt and
// render them in a UI list with width-fitting (the bug we're chasing).
//
// Strategy:
//   1) Search for ASCII strings "t_town", "t_memo", "t_book", "t_shop",
//      "t_book00", "t_book01", "t_book02" in .rdata.
//   2) For each found, list xrefs and the loader functions that use them.
//   3) For each loader, list its callers (consumers of t_town data).
//   4) For each consumer, classify: byte-loop, calls width-calc, calls
//      P3-truncator, has halfwidth handling.
//   5) Decompile top-N consumers that are NOT halfwidth-aware.
//
// We also include a sweep over the 0x14026_0000..0x14028b_700 module
// (CTerminalNotebookWindow / CTerminalQuestWindow) — list of all
// functions there, classified by text-handling pattern.
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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_town_pipeline extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    static final String[] TARGET_STRINGS = {
        "t_town", "t_memo", "t_book", "t_shop",
        "t_book00", "t_book01", "t_book02",
        "t_notepic", "t_notebk", "t_notedt"
    };

    // Functions verified-OK; not viable culprit candidates.
    static final Set<Long> KNOWN_OK = new HashSet<>(Arrays.asList(
        0x140216720L, 0x1402873c0L, 0x140332ba0L,
        0x140212f40L, 0x140215400L, 0x14020e6b0L, 0x140215190L,
        0x140078850L, 0x140078d00L, 0x140078fb0L, 0x140079360L,
        0x1401e5270L, 0x1401e60d0L, 0x140077580L, 0x140078090L,
        0x1401ce2b0L  // P2-patched (item desc)
    ));

    // Already-patched truncator (P3) — its callers are great suspects since
    // they share UI-list pattern.
    static final long F_P3_TRUNC = 0x14028b700L;
    static final long F_WIDTH_CALC = 0x140216720L;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_town_pipeline.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# t_town / t_memo / t_book pipeline hunt");
        log("===========================================================");
        log("");

        // ============ PASS 1: locate target strings ============
        log("############################################################");
        log("# PASS 1: Locate 't_town' / 't_memo' / etc strings in .rdata");
        log("############################################################");
        log("");
        Map<String, List<Address>> stringAddrs = new LinkedHashMap<>();
        for (String s : TARGET_STRINGS) {
            stringAddrs.put(s, findString(s));
        }
        for (Map.Entry<String, List<Address>> e : stringAddrs.entrySet()) {
            log("  '" + e.getKey() + "': " + e.getValue().size() + " occurrence(s)");
            for (Address a : e.getValue()) {
                log("    @ " + a);
            }
        }
        log("");

        // ============ PASS 2: xrefs → loader functions ============
        log("############################################################");
        log("# PASS 2: xrefs to each string → loader function");
        log("############################################################");
        log("");
        Map<Long, Set<String>> loaders = new LinkedHashMap<>();
        for (Map.Entry<String, List<Address>> e : stringAddrs.entrySet()) {
            for (Address a : e.getValue()) {
                ReferenceIterator refIt = currentProgram.getReferenceManager().getReferencesTo(a);
                while (refIt.hasNext()) {
                    Reference r = refIt.next();
                    Address from = r.getFromAddress();
                    Function f = getFunctionContaining(from);
                    if (f != null) {
                        long le = f.getEntryPoint().getOffset();
                        loaders.computeIfAbsent(le, k -> new LinkedHashSet<>())
                               .add(e.getKey() + "@" + a + " (xref from " + from + ")");
                    }
                }
            }
        }
        for (Map.Entry<Long, Set<String>> e : loaders.entrySet()) {
            log("  Loader FUN_" + Long.toHexString(e.getKey()) + ":");
            for (String s : e.getValue()) log("    " + s);
        }
        log("");

        // ============ PASS 3: callers of loaders → UI consumers ============
        log("############################################################");
        log("# PASS 3: Callers of each loader (UI consumers of t_town etc)");
        log("############################################################");
        log("");
        Map<Long, Set<String>> consumers = new LinkedHashMap<>();
        for (Long loader : loaders.keySet()) {
            Function lf = getFunctionAt(toAddr(loader));
            if (lf == null) continue;
            Set<Function> callers = lf.getCallingFunctions(monitor);
            log("  FUN_" + Long.toHexString(loader) + " has " + callers.size() + " callers");
            for (Function f : callers) {
                long e = f.getEntryPoint().getOffset();
                consumers.computeIfAbsent(e, k -> new LinkedHashSet<>())
                         .add("via_loader_" + Long.toHexString(loader));
            }
        }
        log("");

        // ============ PASS 4: callers of P3-truncator (sibling pattern) ============
        log("############################################################");
        log("# PASS 4: Callers of FUN_14028b700 (P3 truncator)");
        log("############################################################");
        log("");
        Function p3 = getFunctionAt(toAddr(F_P3_TRUNC));
        if (p3 != null) {
            Set<Function> p3callers = p3.getCallingFunctions(monitor);
            log("  P3 has " + p3callers.size() + " callers");
            for (Function f : p3callers) {
                long e = f.getEntryPoint().getOffset();
                log("    FUN_" + Long.toHexString(e) + " (" + f.getName() + ")");
                consumers.computeIfAbsent(e, k -> new LinkedHashSet<>())
                         .add("calls_P3_trunc");
            }
        }
        log("");

        // ============ PASS 5: classify consumers ============
        log("############################################################");
        log("# PASS 5: Classify each consumer (text-fit pattern detection)");
        log("############################################################");
        log("");
        log(String.format("%-22s %5s %5s %5s %5s %5s %5s   %s",
            "function", "byteR", "tblL", "wCAL", "wCMP", "trunc", "hwAW", "tags"));

        List<long[]> rows = new ArrayList<>();
        for (Map.Entry<Long, Set<String>> e : consumers.entrySet()) {
            long entry = e.getKey();
            if (KNOWN_OK.contains(entry)) continue;
            Stats s = classify(entry);
            int score = scoreOf(s);
            rows.add(new long[]{score, entry,
                s.byteReadLoops, s.tableLookups, s.widthCalls,
                s.widthCmps, s.truncMarkers, s.halfwidthAware ? 1 : 0});
            log(String.format("%-22s %5d %5d %5d %5d %5d %5d   %s",
                "FUN_" + Long.toHexString(entry),
                s.byteReadLoops, s.tableLookups, s.widthCalls,
                s.widthCmps, s.truncMarkers, s.halfwidthAware ? 1 : 0,
                String.join(",", e.getValue())));
        }
        log("");
        rows.sort((a, b) -> Long.compare(b[0], a[0]));

        // ============ PASS 6: decompile top non-HW candidates ============
        log("############################################################");
        log("# PASS 6: Decompile top candidates (NOT halfwidth-aware)");
        log("############################################################");
        log("");
        int decompiled = 0;
        for (long[] r : rows) {
            if (decompiled >= 10) break;
            long entry = r[1];
            if (r[7] == 1) continue; // halfwidth-aware → skip
            if (r[2] < 1 && r[4] < 1) continue; // no byte-read loop AND no width-call → skip

            log("================================================================");
            log("# FUN_" + Long.toHexString(entry) + "  score=" + r[0] +
                "  byteR=" + r[2] + " tblL=" + r[3] + " wCAL=" + r[4] +
                " wCMP=" + r[5] + " trunc=" + r[6]);
            log("================================================================");
            log("");
            String dec = decompile(entry);
            log(dec);
            log("");
            decompiled++;
        }

        // ============ PASS 7: sweep CTerminalNotebookWindow module ============
        log("############################################################");
        log("# PASS 7: Sweep functions in 0x14026e000..0x14028b700 (notebook module)");
        log("############################################################");
        log("");
        long modStart = 0x14026e000L;
        long modEnd   = 0x14028c000L;
        FunctionIterator fIt = currentProgram.getFunctionManager().getFunctions(true);
        log(String.format("%-22s %5s %5s %5s %5s %5s %5s",
            "function", "byteR", "tblL", "wCAL", "wCMP", "trunc", "hwAW"));
        int swept = 0;
        while (fIt.hasNext()) {
            Function f = fIt.next();
            long e = f.getEntryPoint().getOffset();
            if (e < modStart || e >= modEnd) continue;
            if (KNOWN_OK.contains(e)) continue;
            Stats s = classify(e);
            // Only show interesting ones
            if (s.byteReadLoops < 1 && s.widthCalls < 1 && s.truncMarkers < 1) continue;
            log(String.format("FUN_%-18s %5d %5d %5d %5d %5d %5d   %s",
                Long.toHexString(e),
                s.byteReadLoops, s.tableLookups, s.widthCalls,
                s.widthCmps, s.truncMarkers, s.halfwidthAware ? 1 : 0,
                s.halfwidthAware ? "HW_AWARE" : "!NO_HW"));
            swept++;
        }
        log("");
        log("# Module swept: " + swept + " interesting functions");
        log("");

        log("# DONE");
        out.flush();
        out.close();
        println("Wrote " + outPath);
    }

    // ---------- helpers ----------

    static class Stats {
        int byteReadLoops;
        int tableLookups;
        int widthCalls;
        int widthCmps;
        int truncMarkers;
        boolean halfwidthAware;
    }

    int scoreOf(Stats s) {
        int x = 0;
        if (s.byteReadLoops > 0) x += 1;
        if (s.tableLookups   > 0) x += 1;
        if (s.widthCalls     > 0) x += 3;
        if (s.widthCmps      > 0) x += 1;
        if (s.truncMarkers   > 0) x += 2;
        if (s.halfwidthAware    ) x -= 5;
        return x;
    }

    Stats classify(long addr) {
        Stats s = new Stats();
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) return s;
        AddressSetView body = f.getBody();
        InstructionIterator it = currentProgram.getListing().getInstructions(body, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String mnem = ins.getMnemonicString();
            String full = ins.toString().toLowerCase();

            if (mnem.equals("MOVZX") || mnem.equals("MOV")) {
                if (full.contains("byte ptr [") && !full.contains("*")) s.byteReadLoops++;
                if (full.contains("byte ptr [") && full.contains("*")) s.tableLookups++;
            }
            if (mnem.equals("CALL")) {
                Reference[] refs = ins.getReferencesFrom();
                for (Reference r : refs) {
                    if (r.getReferenceType().isCall()) {
                        long tgt = r.getToAddress().getOffset();
                        if (tgt == F_WIDTH_CALC) s.widthCalls++;
                    }
                }
            }
            if (mnem.equals("CMP")) {
                Object[] ops = ins.getOpObjects(1);
                for (Object o : ops) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v >= 0x10 && v <= 0x400) s.widthCmps++;
                    }
                }
            }
            if (mnem.equals("MOV") && full.contains("byte ptr [")) {
                Object[] ops = ins.getOpObjects(1);
                for (Object o : ops) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x2E || v == 0xA1 || v == 0xA5) s.truncMarkers++;
                    }
                }
            }
            if ((mnem.equals("LEA") || mnem.equals("SUB") || mnem.equals("ADD")) &&
                (full.contains("0x60") || full.contains("0x5f"))) {
                s.halfwidthAware = true;
            }
        }
        return s;
    }

    List<Address> findString(String s) {
        List<Address> result = new ArrayList<>();
        Memory mem = currentProgram.getMemory();
        // scan rdata range
        long scanStart = 0x140300000L;
        long scanEnd   = 0x140500000L;
        Address a = toAddr(scanStart);
        Address aEnd = toAddr(scanEnd);
        byte[] needle = (s + "\0").getBytes();
        while (a != null && a.compareTo(aEnd) < 0) {
            try {
                boolean match = true;
                for (int i = 0; i < needle.length; i++) {
                    if (mem.getByte(a.add(i)) != needle[i]) { match = false; break; }
                }
                if (match) {
                    // ensure preceded by null (start of string)
                    boolean prevNull = false;
                    try { prevNull = mem.getByte(a.add(-1)) == 0; } catch (Exception ex) {}
                    if (prevNull) result.add(a);
                }
            } catch (Exception ex) {}
            a = a.add(1);
        }
        return result;
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
