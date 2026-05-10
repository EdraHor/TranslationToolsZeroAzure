// find_text_loop_no_halfwidth.java
//
// Scan ALL functions in zero.exe and find those that contain a text
// processing loop with byte gating (CMP byte 0x80 or TEST byte+JS or
// (byte<0x80) ASCII fallback) but ZERO references to halfwidth-zone
// boundaries (no CMP with 0xA0/0xA1/0xC0/0xDF/0xE0). Such function
// has likely a simple "byte<0x80 → ASCII; else → SJIS pair" logic
// and silently drops halfwidth bytes.
//
// Filter results to functions that ALSO write to a stream (byte store
// via MOV [reg], r8b or similar). This restricts us to render/copy
// loops, not pure measurement.
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

public class find_text_loop_no_halfwidth extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_text_loop_no_hw.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Text loops without halfwidth-zone awareness");
        log("===========================================================");
        log("");

        // Stats per function:
        //   [0] CMP <r8>, 0x80     (ASCII boundary)
        //   [1] TEST <r8>,<r8> ; JS  (signed byte test)
        //   [2] CMP <r8>, 0x7F    (alt ASCII boundary)
        //   [3] CMP <r8>, halfwidth_byte (0xA0/0xA1/0xC0/0xDF/0xE0)
        //   [4] MOV [reg], <r8>   (byte store)
        //   [5] LEA reg, [reg+0x60] or +0x5F (halfwidth-zone shift trick)
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
                            if (v == 0x80) s[0]++;
                            if (v == 0x7F) s[2]++;
                            if (v == 0xA0 || v == 0xA1 || v == 0xC0 || v == 0xDF || v == 0xE0) s[3]++;
                        }
                    }
                }
            }
            // TEST r8,r8 ; JS
            if (prev != null && prev.getMnemonicString().equals("TEST") && mnem.equals("JS")) {
                String op0 = prev.getDefaultOperandRepresentation(0).toUpperCase();
                String op1 = prev.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.equals(op1) && (op0.endsWith("L") || op0.matches("R\\d+B"))) {
                    s[1]++;
                }
            }
            // MOV [reg], r8 (byte store)
            if (mnem.equals("MOV") && ins.getNumOperands() >= 2) {
                String op0 = ins.getDefaultOperandRepresentation(0);
                String op1 = ins.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.startsWith("byte ptr") && (op1.endsWith("L") || op1.matches("R\\d+B"))) {
                    s[4]++;
                }
            }
            // LEA reg, [reg + 0x60 or 0x5F] — trick for halfwidth shift
            if (mnem.equals("LEA") && ins.getNumOperands() >= 2) {
                Object[] o1 = ins.getOpObjects(1);
                if (o1 != null) for (Object o : o1) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x60 || v == 0x5F) s[5]++;
                    }
                }
            }
            prev = ins;
        }
        log("Scanned " + ic + " instructions across " + stats.size() + " functions.");
        log("");

        // Filter: function has gate (CMP80 or TEST/JS or CMP7F) AND byte store AND no halfwidth
        log("############################################################");
        log("# Filter: gate>0  AND byte_stores>0  AND halfwidth_cmps==0  AND lea_60/5F==0");
        log("############################################################");
        log("");

        List<Function> candidates = new ArrayList<>();
        for (Map.Entry<Function, int[]> e : stats.entrySet()) {
            int[] s = e.getValue();
            int gate = s[0] + s[1] + s[2];
            if (gate == 0) continue;
            if (s[4] == 0) continue;        // need byte stores
            if (s[3] > 0) continue;         // skip ones with halfwidth CMPs
            if (s[5] > 0) continue;         // skip ones using +0x60/+0x5F shift trick
            candidates.add(e.getKey());
        }

        // Skip already-known
        Set<Long> skip = new HashSet<>(Arrays.asList(
            0x1401ce2b0L, 0x140215400L, 0x140212f40L, 0x14020e6b0L,
            0x1401e5270L, 0x140216720L, 0x1402873c0L, 0x140332ba0L,
            0x140078850L, 0x140078d00L, 0x140078fb0L, 0x1400794a0L,
            0x140079360L, 0x140077580L, 0x140078090L, 0x1400772c0L,
            0x1400776a0L, 0x140077420L, 0x140077ec0L,
            0x1400c3c70L, 0x1400c4540L, 0x1400c3a80L, 0x140215190L,
            0x140325b80L, 0x140268050L, 0x140315150L
        ));

        // Sort by combined signal (gate count + stores)
        candidates.sort((a, b) -> {
            int[] sa = stats.get(a); int[] sb = stats.get(b);
            int wa = sa[0] + sa[1] + sa[2] + sa[4];
            int wb = sb[0] + sb[1] + sb[2] + sb[4];
            return wb - wa;
        });

        log(String.format("%-35s  %s", "function", "CMP80 TEST/JS CMP7F HW STORES"));
        for (Function fn : candidates) {
            int[] s = stats.get(fn);
            String tag = skip.contains(fn.getEntryPoint().getOffset()) ? "  (known)" : "";
            log(String.format("%-35s  %5d %7d %5d %2d %6d%s",
                fn.getName() + "@" + fn.getEntryPoint(),
                s[0], s[1], s[2], s[3], s[4], tag));
        }
        log("");
        log("# Total candidates: " + candidates.size());
        log("");

        // Decompile top 12 candidates excluding known
        log("############################################################");
        log("# Decompiled (top 12, excluding known)");
        log("############################################################");
        log("");
        int n = 0;
        for (Function fn : candidates) {
            if (skip.contains(fn.getEntryPoint().getOffset())) continue;
            n++;
            int[] s = stats.get(fn);
            log("================================================================");
            log("# #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                "  CMP80=" + s[0] + " TEST/JS=" + s[1] + " CMP7F=" + s[2] +
                " STORES=" + s[4]);
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 12) {
                log("(capped at 12)");
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
