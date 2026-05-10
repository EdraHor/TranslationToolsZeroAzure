// Decompile candidate parser functions for the 16-bit (t_ittxt) and the
// 32-bit (t_quest/t_memo/...) _dt families. Side-by-side comparison helps
// us see where the pointer width is encoded in the code.
//
// @category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class decomp_parsers extends GhidraScript {

    private static final long[][] TARGETS = {
        // {address, label}
        {0x1402f9650L, 0}, // 16b candidate: heavy on t_ittxt + t_ittxt2
        {0x14025bd90L, 0}, // 16b candidate: t_ittxt + t_town
        {0x140215400L, 0}, // 16b candidate: t_ittxt + t_ittxt2
        {0x1401f1c90L, 0}, // 16b candidate: t_ittxt + ittxt2 + quartz (broad)
        {0x14026f400L, 1}, // 32b dispatcher: reads ALL 32-bit buffers
        {0x1402a4940L, 1}, // 32b candidate: heavy memo+quest
        {0x1402a7af0L, 1}, // 32b candidate: heaviest memo+quest reader
        {0x1402a9370L, 1}, // 32b candidate: 4 hits on t_quest
    };

    private static final String[] LABELS = {"16-bit candidate", "32-bit candidate"};

    private static final String OUT_PATH =
        "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_parsers.txt";

    @Override
    public void run() throws Exception {
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        try (PrintWriter w = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(OUT_PATH), StandardCharsets.UTF_8))) {

            for (long[] row : TARGETS) {
                long addr = row[0];
                int kind = (int) row[1];
                Address a = toAddr(addr);
                Function func = getFunctionContaining(a);

                w.println("====================================================");
                w.println("=== [" + LABELS[kind] + "] "
                        + (func != null ? func.getName() + " @ " + func.getEntryPoint()
                                        : "NO FUNC at " + a)
                        + " ===");
                w.println("====================================================");
                if (func == null) { w.println(); continue; }

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
