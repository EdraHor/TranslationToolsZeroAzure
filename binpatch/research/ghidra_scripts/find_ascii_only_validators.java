// find_ascii_only_validators.java
//
// Hunt for the *real* tooltip-path text handler.
//
// Known facts:
//   - Item descriptions break on the first halfwidth byte (>=0x80).
//   - Item names work fine on halfwidth.
//   - Patching FUN_140078850 (encoding detector) had no effect, so
//     the description handler does NOT go through FUN_140077420/ec0.
//
// The handler we're looking for is therefore a separate text-loop that
// trusts each input byte to be ASCII and aborts on >=0x80. Tell-tale
// pattern in x86-64:
//
//   1. read byte: MOV AL, [rXX]   or   MOVZX EAX, byte ptr [rXX]
//   2. test sign: TEST AL, AL  /  CMP AL, 0x80
//   3. branch out: JS exit  /  JNS continue  /  JAE exit / JL exit
//   4. STORE / RENDER the byte if continue
//   5. inc pointer, loop
//
// We scan every function and count "ASCII-only break" signatures:
//   TEST AL,AL ; JS  ...      (jumps if signed bit set => byte >= 0x80)
//   CMP  AL,0x80 ; JAE/JNB    (jumps if byte >= 0x80)
//   CMP  AL,0x7F ; JA         (jumps if byte > 0x7F)
//
// We also look for functions that reference DAT_1404b1d08 (the SJIS
// table loaded from sjisutf8.dat) — these are decoders, not what we
// want — so we can de-prioritize them.
//
//@category TrailsFromZero
//@menupath Tools.Misc.find_ascii_only_validators
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

public class find_ascii_only_validators extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_ascii_validators.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# ASCII-only break-loop hunt");
        log("===========================================================");
        log("");

        // Track per-function counts of:
        //   testAlAlAfterMovByte: TEST AL,AL right after a byte load
        //   jsAfterTestAl       : JS within 4 instr of TEST AL,AL
        //   cmp80               : CMP AL,0x80 (or REG,0x80) inside loop
        //   cmp7F               : CMP AL,0x7F
        Map<Function, int[]> stats = new HashMap<>();
        // index: 0=test/al, 1=js, 2=cmp80, 3=cmp7F, 4=touches_DAT_1404b1d08
        final int IDX_TEST = 0, IDX_JS = 1, IDX_CMP80 = 2, IDX_CMP7F = 3, IDX_TOUCH_TBL = 4;

        long sjisTable = 0x1404b1d08L;
        Listing listing = currentProgram.getListing();

        // pre-pass: build list of all instructions per function
        Map<Function, List<Instruction>> fnInstrs = new HashMap<>();
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            Function fn = getFunctionContaining(ins.getAddress());
            if (fn == null) continue;
            fnInstrs.computeIfAbsent(fn, k -> new ArrayList<>()).add(ins);
        }
        log("Indexed instructions in " + fnInstrs.size() + " functions.");
        log("");

        for (Map.Entry<Function, List<Instruction>> e : fnInstrs.entrySet()) {
            Function fn = e.getKey();
            List<Instruction> ins = e.getValue();
            int[] s = new int[5];

            for (int i = 0; i < ins.size(); i++) {
                Instruction in = ins.get(i);
                String mnem = in.getMnemonicString();

                // touches SJIS conv table?
                Reference[] refs = in.getReferencesFrom();
                for (Reference r : refs) {
                    if (r.getReferenceType().isData() && r.getToAddress().getOffset() == sjisTable) {
                        s[IDX_TOUCH_TBL]++;
                    }
                }
                int nOps = in.getNumOperands();
                for (int op = 0; op < nOps; op++) {
                    Object[] objs = in.getOpObjects(op);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof Address && ((Address) o).getOffset() == sjisTable) {
                            s[IDX_TOUCH_TBL]++;
                        }
                    }
                }

                // TEST AL, AL
                if (mnem.equals("TEST") && nOps >= 2) {
                    String op0 = in.getDefaultOperandRepresentation(0);
                    String op1 = in.getDefaultOperandRepresentation(1);
                    if (op0.equalsIgnoreCase("AL") && op1.equalsIgnoreCase("AL")) {
                        s[IDX_TEST]++;
                        // is next instruction JS ?
                        if (i + 1 < ins.size()) {
                            Instruction nxt = ins.get(i+1);
                            if (nxt.getMnemonicString().equals("JS")) {
                                s[IDX_JS]++;
                            }
                        }
                    }
                }

                // CMP AL, 0x80
                if (mnem.equals("CMP") && nOps >= 2) {
                    String op0 = in.getDefaultOperandRepresentation(0);
                    Object[] op1obj = in.getOpObjects(1);
                    if (op1obj != null) {
                        for (Object o : op1obj) {
                            if (o instanceof Scalar) {
                                long v = ((Scalar) o).getUnsignedValue();
                                if (v == 0x80 && (op0.equalsIgnoreCase("AL")
                                                  || op0.equalsIgnoreCase("CL")
                                                  || op0.equalsIgnoreCase("DL")
                                                  || op0.equalsIgnoreCase("BL"))) {
                                    s[IDX_CMP80]++;
                                }
                                if (v == 0x7F && (op0.equalsIgnoreCase("AL")
                                                  || op0.equalsIgnoreCase("CL")
                                                  || op0.equalsIgnoreCase("DL")
                                                  || op0.equalsIgnoreCase("BL"))) {
                                    s[IDX_CMP7F]++;
                                }
                            }
                        }
                    }
                }
            }

            // Filter: function must have at least one of the ASCII-only signals
            int signal = s[IDX_JS] + s[IDX_CMP80] + s[IDX_CMP7F];
            if (signal == 0) continue;
            stats.put(fn, s);
        }

        log("# Functions with ASCII-only break signature:");
        log("");

        // Sort by signal strength: JS > CMP80 > CMP7F
        List<Map.Entry<Function, int[]>> sorted = new ArrayList<>(stats.entrySet());
        sorted.sort((a, b) -> {
            int sa = a.getValue()[IDX_JS]*4 + a.getValue()[IDX_CMP80]*3 + a.getValue()[IDX_CMP7F]*2;
            int sb = b.getValue()[IDX_JS]*4 + b.getValue()[IDX_CMP80]*3 + b.getValue()[IDX_CMP7F]*2;
            return sb - sa;
        });

        log(String.format("%-35s  %5s  %5s  %5s  %5s  %s",
            "function", "JS", "CMP80", "CMP7F", "TBL", "(TBL = touches sjisutf8 table)"));
        for (Map.Entry<Function, int[]> e : sorted) {
            Function fn = e.getKey();
            int[] s = e.getValue();
            log(String.format("%-35s  %5d  %5d  %5d  %5d",
                fn.getName() + "@" + fn.getEntryPoint(),
                s[IDX_JS], s[IDX_CMP80], s[IDX_CMP7F], s[IDX_TOUCH_TBL]));
        }
        log("");

        // Decompile top 10 candidates that DO NOT touch SJIS table
        log("############################################################");
        log("# Decompiled top-10 candidates that DON'T use SJIS table");
        log("# (those that do are normal SJIS decoders, not our culprit)");
        log("############################################################");
        log("");

        int dec = 0;
        for (Map.Entry<Function, int[]> e : sorted) {
            Function fn = e.getKey();
            int[] s = e.getValue();
            if (s[IDX_TOUCH_TBL] > 0) continue;     // skip real SJIS decoders
            if (s[IDX_JS] + s[IDX_CMP80] + s[IDX_CMP7F] < 1) break;
            dec++;
            log("================================================================");
            log("# Candidate #" + dec + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                "   JS=" + s[IDX_JS] + " CMP80=" + s[IDX_CMP80] + " CMP7F=" + s[IDX_CMP7F]);
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (dec >= 10) break;
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
