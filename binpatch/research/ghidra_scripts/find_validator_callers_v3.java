// find_validator_callers_v3.java
//
// Two tasks:
//   1) Scan ALL CALL instructions in zero.exe and find every site that
//      transfers control to:
//        - FUN_1400c3c70 (UTF-8 validator A)
//        - FUN_1400c4540 (UTF-8 validator B)
//        - 1400c3a80     (thunk -> FUN_1400c4540)
//      Decompile each caller. We need to know who actually goes through
//      these validators -- item descriptions, books, memos, etc.
//
//   2) Search the whole binary for any function whose body contains
//      CMP/SUB with all THREE constants {0x80, 0xC0, 0xE0} (the UTF-8
//      decoder boundary signature). The two we already know likely aren't
//      the only ones; an item-tooltip handler might have its own copy.
//
//@category TrailsFromZero
//@menupath Tools.Misc.find_validator_callers_v3
//@runtime Java

import java.io.PrintWriter;
import java.io.FileWriter;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_validator_callers_v3 extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_validator_callers.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# UTF-8 validator callers + signature search v3");
        log("===========================================================");
        log("");

        // ---- Targets: any CALL/JMP whose destination is one of these
        Set<Long> targets = new HashSet<>();
        targets.add(0x1400c3c70L);
        targets.add(0x1400c4540L);
        targets.add(0x1400c3a80L); // thunk

        // Maps for output
        Map<Long, List<Address>> callsTo = new HashMap<>();
        for (Long t : targets) callsTo.put(t, new ArrayList<>());

        // For task 2: per-function magic byte set
        int[] utf8Sig = {0x80, 0xC0, 0xE0};
        Map<Function, Set<Integer>> sigHits = new HashMap<>();

        // ---- single instruction scan, do both tasks
        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);
        long instCount = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            instCount++;
            String mnem = ins.getMnemonicString();

            // --- task 1: CALL / JMP targets
            if (mnem.equals("CALL") || mnem.equals("JMP")) {
                int nOps = ins.getNumOperands();
                for (int i = 0; i < nOps; i++) {
                    Object[] objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof Address) {
                            long ta = ((Address) o).getOffset();
                            if (targets.contains(ta)) {
                                callsTo.get(ta).add(ins.getAddress());
                            }
                        }
                    }
                }
                // also harvest references on this instruction
                Reference[] refs = ins.getReferencesFrom();
                for (Reference r : refs) {
                    if (r.getReferenceType().isCall() || r.getReferenceType().isJump()) {
                        long ta = r.getToAddress().getOffset();
                        if (targets.contains(ta)) {
                            // avoid dupes
                            if (!callsTo.get(ta).contains(ins.getAddress())) {
                                callsTo.get(ta).add(ins.getAddress());
                            }
                        }
                    }
                }
            }

            // --- task 2: UTF-8 magic byte signature
            if (mnem.equals("CMP") || mnem.equals("SUB") || mnem.equals("AND")) {
                int nOps = ins.getNumOperands();
                for (int i = 0; i < nOps; i++) {
                    Object[] objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            for (int m : utf8Sig) {
                                if (v == m) {
                                    Function fn = getFunctionContaining(ins.getAddress());
                                    if (fn != null) {
                                        sigHits.computeIfAbsent(fn, k -> new TreeSet<>()).add(m);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        log("Scanned " + instCount + " instructions.");
        log("");

        // ============================================================
        // PART 1: who calls the validators?
        // ============================================================
        log("############################################################");
        log("# PART 1 — callers of UTF-8 validators (CALL/JMP targets)");
        log("############################################################");
        log("");

        for (Long t : targets) {
            log("======================================================");
            log("# Target: 0x" + Long.toHexString(t));
            log("======================================================");
            List<Address> sites = callsTo.get(t);
            log("# Direct call/jmp sites: " + sites.size());
            Set<Function> callerFns = new LinkedHashSet<>();
            for (Address sa : sites) {
                Function fn = getFunctionContaining(sa);
                String fname = (fn != null) ? fn.getName() + "@" + fn.getEntryPoint() : "(none)";
                log("  from " + sa + "   in " + fname);
                if (fn != null) callerFns.add(fn);
            }
            log("");
            log("# Distinct caller functions: " + callerFns.size());
            log("");

            int n = 0;
            for (Function fn : callerFns) {
                n++;
                log("--------------------------------------------------------");
                log("# Caller #" + n + ": " + fn.getName() + " @ " + fn.getEntryPoint());
                log("--------------------------------------------------------");
                log(decompileFn(fn));
                log("");
                if (n >= 12) {
                    log("(capped at 12 callers)");
                    break;
                }
            }
            log("");
        }

        // ============================================================
        // PART 2: any other function with full UTF-8 boundary signature
        // ============================================================
        log("############################################################");
        log("# PART 2 — ALL functions with {0x80, 0xC0, 0xE0} signature");
        log("# (potential additional UTF-8 decoders)");
        log("############################################################");
        log("");

        List<Map.Entry<Function, Set<Integer>>> sorted = new ArrayList<>(sigHits.entrySet());
        sorted.sort((a, b) -> b.getValue().size() - a.getValue().size());

        log("# Functions with all three UTF-8 magic bytes:");
        int totalFull = 0;
        List<Function> fullSigFns = new ArrayList<>();
        for (Map.Entry<Function, Set<Integer>> e : sorted) {
            if (e.getValue().size() == 3) {
                Function fn = e.getKey();
                log("  " + fn.getName() + "@" + fn.getEntryPoint());
                fullSigFns.add(fn);
                totalFull++;
            }
        }
        log("# Total: " + totalFull);
        log("");

        log("# Functions with exactly two UTF-8 magic bytes (0x80 + 0xC0 OR 0x80 + 0xE0 etc.):");
        int totalTwo = 0;
        for (Map.Entry<Function, Set<Integer>> e : sorted) {
            if (e.getValue().size() == 2) {
                Function fn = e.getKey();
                log("  " + fn.getName() + "@" + fn.getEntryPoint() + "  bytes=" + e.getValue());
                totalTwo++;
            }
        }
        log("# Total: " + totalTwo);
        log("");

        // Decompile any full-sig fn we haven't already shown
        log("############################################################");
        log("# PART 2.2 — decompile full-signature functions");
        log("############################################################");
        log("");
        Set<Long> alreadyKnown = new HashSet<>();
        alreadyKnown.add(0x1400c3c70L);
        alreadyKnown.add(0x1400c4540L);
        alreadyKnown.add(0x140078d00L);
        alreadyKnown.add(0x1400c3c70L);
        alreadyKnown.add(0x140078850L);
        for (Function fn : fullSigFns) {
            long ea = fn.getEntryPoint().getOffset();
            log("================================================================");
            log("# Full-sig fn: " + fn.getName() + " @ " + fn.getEntryPoint() +
                (alreadyKnown.contains(ea) ? "   (ALREADY ANALYZED)" : "   (NEW!)"));
            log("================================================================");
            if (!alreadyKnown.contains(ea)) {
                log(decompileFn(fn));
            } else {
                log("  (decomp omitted — see out_sjis_converter_v2.txt)");
            }
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
