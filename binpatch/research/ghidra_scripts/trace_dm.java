// Trace DataManager: decompile callers of the loaders, hunt for the third
// loader (t_book/t_shop), and dump strings starting with "t_".
// @category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class trace_dm extends GhidraScript {

    // Callers of the two known loaders. We want to see where the DM object
    // (param_1) is allocated and where it is parked globally.
    private static final long[] CALLERS = new long[] {
        0x14026fdb0L,   // caller of FUN_140279a10 (16-bit family)
        0x14026d9d0L,   // caller of FUN_14026e990 (32-bit family)
        0x14012a114L,   // calls both
    };

    // Extra ASCII patterns for the third loader. We try lots of variants.
    private static final String[] PATTERNS = {
        "book",
        "shop",
        "%02d._dt",
        "%d._dt",
        "%s%02d",
        "%s%d",
        "%s%02d._dt",
        "%s%d._dt",
        "t_book%02d",
        "t_book%d",
        "t_shop%02d",
        "t_shop%d",
        "scena/%s",
        "data/%s",
        "monobook",
        "calendar",
    };

    private static final String OUT_PATH =
        "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_trace_dm.txt";

    private List<Address> findAllStrings(String needle) throws Exception {
        byte[] pattern = (needle + "\0").getBytes(StandardCharsets.US_ASCII);
        Memory mem = currentProgram.getMemory();
        List<Address> hits = new ArrayList<>();
        Address start = mem.getMinAddress();
        while (start != null) {
            Address found = mem.findBytes(start, pattern, null, true, monitor);
            if (found == null) break;
            hits.add(found);
            try {
                start = found.add(1);
            } catch (Exception e) {
                break;
            }
        }
        return hits;
    }

    private String fnName(Address addr) {
        if (addr == null) return "<null>";
        Function f = getFunctionContaining(addr);
        if (f == null) return "<no func>";
        return f.getName() + "@" + f.getEntryPoint();
    }

    @Override
    public void run() throws Exception {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        try (PrintWriter w = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(OUT_PATH), StandardCharsets.UTF_8))) {

            // ========== PART A: scan defined ASCII strings starting with "t_"
            // ==========
            w.println("############################################################");
            w.println("# PART A — defined strings starting with 't_'");
            w.println("############################################################");
            w.println();

            Listing listing = currentProgram.getListing();
            DataIterator dit = listing.getDefinedData(true);
            int tCount = 0;
            while (dit.hasNext() && !monitor.isCancelled()) {
                Data d = dit.next();
                if (!d.hasStringValue()) continue;
                Object val = d.getValue();
                if (!(val instanceof String)) continue;
                String s = (String) val;
                if (s.length() < 3 || s.length() > 32) continue;
                if (!s.startsWith("t_")) continue;
                w.println("  " + d.getAddress() + "  '" + s + "'");
                int n = 0;
                for (Reference r : refMgr.getReferencesTo(d.getAddress())) {
                    w.println("    xref from " + r.getFromAddress()
                            + "  in " + fnName(r.getFromAddress()));
                    n++;
                    if (n >= 8) { w.println("    ... (truncated)"); break; }
                }
                tCount++;
                if (tCount > 200) {
                    w.println("  ... (more than 200 t_ strings, truncated)");
                    break;
                }
            }
            w.println();

            // ========== PART B: extra filename patterns ==========
            w.println("############################################################");
            w.println("# PART B — additional filename patterns");
            w.println("############################################################");
            w.println();

            for (String pat : PATTERNS) {
                w.println("---- pattern: '" + pat + "' ----");
                List<Address> hits = findAllStrings(pat);
                if (hits.isEmpty()) {
                    w.println("  (not found)");
                    w.println();
                    continue;
                }
                for (Address h : hits) {
                    w.println("  string @ " + h);
                    int n = 0;
                    for (Reference r : refMgr.getReferencesTo(h)) {
                        w.println("    xref from " + r.getFromAddress()
                                + "  type=" + r.getReferenceType()
                                + "  in " + fnName(r.getFromAddress()));
                        n++;
                        if (n >= 12) { w.println("    ... (truncated)"); break; }
                    }
                    if (n == 0) w.println("    (no xrefs)");
                }
                w.println();
            }

            // ========== PART C: decompile callers of known loaders ==========
            w.println("############################################################");
            w.println("# PART C — decompile callers of the two known loaders");
            w.println("############################################################");
            w.println();

            Set<Long> seen = new HashSet<>();
            for (long addr : CALLERS) {
                if (!seen.add(addr)) continue;
                Address a = toAddr(addr);
                Function func = getFunctionContaining(a);

                w.println("====================================================");
                if (func == null) {
                    w.println("=== NO FUNCTION at " + a + " ===");
                    w.println();
                    continue;
                }
                w.println("=== " + func.getName() + " @ " + func.getEntryPoint() + " ===");
                w.println("====================================================");

                w.print("CALLERS: ");
                int n = 0;
                for (Function f : func.getCallingFunctions(mon)) {
                    if (n > 0) w.print(", ");
                    w.print(f.getName() + "@" + f.getEntryPoint());
                    n++;
                    if (n >= 20) { w.print(", ..."); break; }
                }
                w.println();

                w.print("CALLEES: ");
                n = 0;
                for (Function f : func.getCalledFunctions(mon)) {
                    if (n > 0) w.print(", ");
                    w.print(f.getName() + "@" + f.getEntryPoint());
                    n++;
                    if (n >= 30) { w.print(", ..."); break; }
                }
                w.println();
                w.println();

                DecompileResults res = dec.decompileFunction(func, 180, mon);
                if (res.decompileCompleted()) {
                    w.println(res.getDecompiledFunction().getC());
                } else {
                    w.println("DECOMPILE FAILED: " + res.getErrorMessage());
                }
                w.println();
            }

            w.println("=== END ===");
        }

        println("Written to: " + OUT_PATH);
    }
}
