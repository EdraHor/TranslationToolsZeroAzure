// Find code that reads buffer pointers from lpGame at known offsets:
//   t_ittxt   = lpGame + 0x721178   (16-bit family)
//   t_ittxt2  = lpGame + 0x721188
//   t_item    = lpGame + 0x721170
//   t_magic   = lpGame + 0x721198
//   t_quest   = lpGame + 0x72ca98   (32-bit family)
//   t_name    = lpGame + 0x72ca88
//   t_orb     = lpGame + 0x72caa8
// Strategy: find every place in code where the offset appears as a 4-byte
// immediate (little-endian). Group by containing function.
//
// Also decompile FUN_1402bd6a0 (t_shop loader) and FUN_140294530 (t_mons),
// to see how they differ from the two known loaders.
//
// @category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class find_buffer_readers extends GhidraScript {

    // Pairs of {label, offset}. Will be searched as 4-byte LE immediates.
    private static final Object[][] OFFSETS = {
        {"t_item   (16b)", 0x721170L},
        {"t_ittxt  (16b)", 0x721178L},
        {"t_item2  (16b)", 0x721180L},
        {"t_ittxt2 (16b)", 0x721188L},
        {"t_quartz (16b)", 0x721190L},
        {"t_magic  (16b)", 0x721198L},
        {"t_crfget (16b)", 0x7211a0L},
        {"t_magqrt (16b)", 0x7211a8L},
        {"t_town   (16b)", 0x7211b0L},
        {"t_cook   (16b)", 0x7211b8L},
        {"t_trade  (16b)", 0x7211c0L},
        {"t_name   (32b)", 0x72ca88L},
        {"t_sltget (32b)", 0x72ca90L},
        {"t_quest  (32b)", 0x72ca98L},
        {"t_memo   (32b)", 0x72caa0L},
        {"t_orb    (32b)", 0x72caa8L},
        {"t_world  (32b)", 0x72cab0L},
        {"t_bgm    (32b)", 0x72cac8L},
        {"t_record (32b)", 0x72cad0L},
        {"t_msas   (32b)", 0x72cad8L},
    };

    // Loaders we still want decompiled in full
    private static final long[] EXTRA_LOADERS = {
        0x1402bd6a0L, // t_shop loader
        0x140294530L, // t_mons loader
    };

    private static final String OUT_PATH =
        "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_buffer_readers.txt";

    private byte[] le32(long v) {
        return new byte[] {
            (byte)(v & 0xff),
            (byte)((v >> 8) & 0xff),
            (byte)((v >> 16) & 0xff),
            (byte)((v >> 24) & 0xff),
        };
    }

    private List<Address> findAllBytes(byte[] pattern) throws Exception {
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
        Function f = getFunctionContaining(addr);
        if (f == null) return "<no func>";
        return f.getName() + "@" + f.getEntryPoint();
    }

    private String safeInstruction(Address addr) {
        // Return disassembly of instruction *containing* this address, if any.
        Instruction ins = getInstructionContaining(addr);
        if (ins == null) return "<no instruction>";
        return ins.getAddress() + ": " + ins.toString();
    }

    @Override
    public void run() throws Exception {
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        try (PrintWriter w = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(OUT_PATH), StandardCharsets.UTF_8))) {

            // ============ PART A: hunt buffer-pointer offsets ============
            w.println("############################################################");
            w.println("# PART A — code sites that load lpGame->[buffer]");
            w.println("############################################################");
            w.println();

            for (Object[] row : OFFSETS) {
                String label = (String) row[0];
                long off = (Long) row[1];
                byte[] pat = le32(off);

                w.println("---- " + label + " offset 0x" + Long.toHexString(off) + " ----");
                List<Address> raw = findAllBytes(pat);

                // Only keep hits that are inside a function, dedupe by function.
                Map<String, List<Address>> byFunc = new LinkedHashMap<>();
                int rawCount = raw.size();
                int codeCount = 0;
                for (Address a : raw) {
                    Function f = getFunctionContaining(a);
                    if (f == null) continue;
                    codeCount++;
                    String key = f.getName() + "@" + f.getEntryPoint();
                    byFunc.computeIfAbsent(key, k -> new ArrayList<>()).add(a);
                }
                w.println("  raw matches: " + rawCount + ", in-function matches: " + codeCount
                        + ", distinct functions: " + byFunc.size());

                int shown = 0;
                for (Map.Entry<String, List<Address>> e : byFunc.entrySet()) {
                    w.println("  fn " + e.getKey() + "  hits=" + e.getValue().size());
                    int siteShown = 0;
                    for (Address a : e.getValue()) {
                        w.println("    @ " + a + "  >>  " + safeInstruction(a));
                        siteShown++;
                        if (siteShown >= 4) {
                            w.println("    ... " + (e.getValue().size() - 4) + " more in this fn");
                            break;
                        }
                    }
                    shown++;
                    if (shown >= 25) {
                        w.println("  ... (" + (byFunc.size() - 25) + " more functions truncated)");
                        break;
                    }
                }
                w.println();
            }

            // ============ PART B: decompile extra loaders ============
            w.println("############################################################");
            w.println("# PART B — decompile other loader candidates");
            w.println("############################################################");
            w.println();

            for (long addr : EXTRA_LOADERS) {
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
