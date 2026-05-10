// Decompile candidate _dt loader/registrar functions and hunt for missing
// filename templates ("t_book%...", "t_shop%...", etc).
// @category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class dump_loaders extends GhidraScript {

    // Functions discovered via find_dt_loaders.java
    private static final long[] FUNC_ADDRS = new long[] {
        0x140279a10L,   // 16-bit registrar (item/ittxt/magic/quartz/crfget)
        0x14026e990L,   // 32-bit registrar (quest/name)
    };

    // Patterns that may be used by sprintf to build dynamic filenames.
    // Each pattern is searched as ASCII + NUL.
    private static final String[] FILENAME_PATTERNS = {
        "t_book",
        "t_shop",
        "t_book%",
        "t_shop%",
        "t_book%02d",
        "t_shop%02d",
        "t_book%d",
        "t_shop%d",
        // Generic "t_xxx" probes
        "t_town",
        "t_npc",
        "t_voice",
        "t_mons",
        "t_mstqrt",
        "t_dt%",
        "t_%s",
        ".dt",
        "._dt",
        "%s._dt",
        "%s%02d._dt",
    };

    private static final String OUT_PATH =
        "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_loaders.txt";

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

            // ---------- Part A: dynamic filename patterns ----------
            w.println("############################################################");
            w.println("# PART A — dynamic filename pattern hunt");
            w.println("############################################################");
            w.println();

            for (String pat : FILENAME_PATTERNS) {
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
                        Address src = r.getFromAddress();
                        w.println("    xref from " + src
                                + "  type=" + r.getReferenceType()
                                + "  in " + fnName(src));
                        n++;
                    }
                    if (n == 0) w.println("    (no xrefs)");
                }
                w.println();
            }

            // ---------- Part B: decompile candidate loader functions ----------
            w.println("############################################################");
            w.println("# PART B — decompile candidate registrar/loader functions");
            w.println("############################################################");
            w.println();

            for (long addr : FUNC_ADDRS) {
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

                // Callers / callees summary
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

                // Decompile
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
