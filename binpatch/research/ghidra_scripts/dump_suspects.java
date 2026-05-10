// dump_suspects.java
//
// Decompile and ASM-dump a list of suspect functions in the notebook module
// (0x14026e000..0x14028c000) so we can compare:
//
// HW_AWARE siblings of FUN_14028b700 (P3) — these are width-fitters that
// work correctly, useful as reference:
//   FUN_140287b50, FUN_14028aac0, FUN_140289a30
//
// !NO_HW candidates with high wCMP / tblL — possible culprits for t_town:
//   FUN_14027c5e0  (wCMP=22)
//   FUN_14027c880  (tblL=4 wCMP=11)
//   FUN_140278e30  (tblL=9 wCMP=11)
//   FUN_140280140  (byteR=12 wCMP=13)
//   FUN_14027dd90  (byteR=8 wCMP=6)
//
// Render-related siblings (called next to P3):
//   FUN_140289800  (called from FUN_1401cfd40 right next to FUN_14028b700)
//   FUN_1402a6c40  (calls P3, was filtered out from previous decomp)
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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class dump_suspects extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    static final long[] TARGETS = {
        // HW_AWARE siblings — reference for "good" pattern
        0x140287b50L,
        0x14028aac0L,
        0x140289a30L,
        // !NO_HW notebook-module candidates
        0x14027c5e0L,
        0x14027c880L,
        0x140278e30L,
        0x140280140L,
        0x14027dd90L,
        // P3 callers / siblings
        0x140289800L,
        0x1402a6c40L,
    };

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_suspects.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Decompile + ASM dump of t_town width-fitter suspects");
        log("===========================================================");
        log("");

        for (long addr : TARGETS) {
            log("================================================================");
            log("# FUN_" + Long.toHexString(addr));
            log("================================================================");
            log("");

            // Decompile
            log("---- DECOMPILED ----");
            log(decompile(addr));
            log("");

            // ASM dump
            log("---- ASSEMBLY ----");
            dumpAsm(addr);
            log("");
        }

        log("# DONE");
        out.flush();
        out.close();
        println("Wrote " + outPath);
    }

    String decompile(long addr) {
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) return "  [no function at 0x" + Long.toHexString(addr) + "]";
        DecompileResults r = decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());
        if (r == null || !r.decompileCompleted()) return "  [decompile failed]";
        return r.getDecompiledFunction().getC();
    }

    void dumpAsm(long addr) {
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) {
            log("  [no function]");
            return;
        }
        AddressSetView body = f.getBody();
        InstructionIterator it = currentProgram.getListing().getInstructions(body, true);
        int count = 0;
        while (it.hasNext() && count < 600) {
            Instruction ins = it.next();
            log(String.format("  %s   %-20s %s",
                ins.getAddress().toString(),
                ins.getMnemonicString(),
                operandsString(ins)));
            count++;
        }
        if (it.hasNext()) log("  [...truncated at 600 instructions...]");
    }

    String operandsString(Instruction ins) {
        StringBuilder sb = new StringBuilder();
        int n = ins.getNumOperands();
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append(ins.getDefaultOperandRepresentation(i));
        }
        return sb.toString();
    }

    void log(String s) {
        out.println(s);
        println(s);
    }
}
