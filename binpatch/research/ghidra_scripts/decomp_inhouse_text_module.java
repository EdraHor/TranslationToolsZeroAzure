// decomp_inhouse_text_module.java
//
// Decompile the suspected in-house text module functions and list their
// callers. The CRT validators FUN_1400c3c70/FUN_1400c4540 have no direct
// callers, so they are likely standard library helpers, not used by the
// tooltip-path. The real culprit is more likely in the contiguous block
// of in-house converters at:
//
//   FUN_140078850
//   FUN_140078d00
//   FUN_140078fb0   (already known: SJIS->UTF-8, halfwidth correct)
//   FUN_1400794a0
//
// Also dump CMP magic-byte patch sites for each.
//
//@category TrailsFromZero
//@menupath Tools.Misc.decomp_inhouse_text_module
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

public class decomp_inhouse_text_module extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_inhouse_text.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        long[] targets = { 0x140078850L, 0x140078d00L, 0x1400794a0L, 0x140078fb0L };

        log("===========================================================");
        log("# In-house text module @ 0x140078000-0x14007a000");
        log("===========================================================");
        log("");

        // pre-build call/jmp map across all instructions
        Set<Long> tset = new HashSet<>();
        for (long t : targets) tset.add(t);
        Map<Long, List<Address>> callsTo = new HashMap<>();
        for (long t : targets) callsTo.put(t, new ArrayList<>());

        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            String mnem = ins.getMnemonicString();
            if (!mnem.equals("CALL") && !mnem.equals("JMP")) continue;
            int nOps = ins.getNumOperands();
            for (int i = 0; i < nOps; i++) {
                Object[] objs = ins.getOpObjects(i);
                if (objs == null) continue;
                for (Object o : objs) {
                    if (o instanceof Address) {
                        long ta = ((Address) o).getOffset();
                        if (tset.contains(ta)) callsTo.get(ta).add(ins.getAddress());
                    }
                }
            }
            Reference[] refs = ins.getReferencesFrom();
            for (Reference r : refs) {
                if (r.getReferenceType().isCall() || r.getReferenceType().isJump()) {
                    long ta = r.getToAddress().getOffset();
                    if (tset.contains(ta) && !callsTo.get(ta).contains(ins.getAddress())) {
                        callsTo.get(ta).add(ins.getAddress());
                    }
                }
            }
        }

        for (long ta : targets) {
            Address aa = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ta);
            Function fn = getFunctionAt(aa);
            log("################################################################");
            log("# " + (fn != null ? fn.getName() : "(none)") + " @ " + Long.toHexString(ta));
            log("################################################################");
            if (fn == null) {
                log("# NOT A FUNCTION ENTRY POINT!");
                log("");
                continue;
            }
            log("# body: " + fn.getBody().getMinAddress() + " .. " + fn.getBody().getMaxAddress());
            log("# size: " + fn.getBody().getNumAddresses() + " bytes");
            log("");

            // patch sites
            log("## CMP magic-byte sites (potential patch points):");
            int[] mb = {0x80, 0xA0, 0xA1, 0xC0, 0xDF, 0xE0, 0xF0, 0xF8, 0xFC};
            for (Address a : fn.getBody().getAddresses(true)) {
                Instruction ins = listing.getInstructionAt(a);
                if (ins == null) continue;
                String mnem = ins.getMnemonicString();
                if (!mnem.equals("CMP") && !mnem.equals("SUB") && !mnem.equals("AND")) continue;
                int nOps = ins.getNumOperands();
                for (int i = 0; i < nOps; i++) {
                    Object[] objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            for (int t : mb) {
                                if (v == t) {
                                    StringBuilder hex = new StringBuilder();
                                    try {
                                        byte[] bytes = ins.getBytes();
                                        for (byte b : bytes) hex.append(String.format("%02X ", b & 0xFF));
                                    } catch (Exception e) {}
                                    log(String.format("  %s   %-30s   bytes=[%s]",
                                            ins.getAddress(),
                                            mnem + " " + ins.getDefaultOperandRepresentation(0)
                                                + ", " + ins.getDefaultOperandRepresentation(1),
                                            hex.toString().trim()));
                                }
                            }
                        }
                    }
                }
            }
            log("");

            // direct callers
            log("## Direct CALL/JMP sites:");
            List<Address> sites = callsTo.get(ta);
            log("  count: " + sites.size());
            Set<Function> callerFns = new LinkedHashSet<>();
            for (Address sa : sites) {
                Function cf = getFunctionContaining(sa);
                String fname = (cf != null) ? cf.getName() + "@" + cf.getEntryPoint() : "(none)";
                log("  from " + sa + "   in " + fname);
                if (cf != null) callerFns.add(cf);
            }
            log("  distinct caller functions: " + callerFns.size());
            log("");

            // decompile the function itself
            log("## Decompiled function body:");
            log(decompileFn(fn));
            log("");

            // decompile a few callers
            log("## Decompiled callers (capped at 4):");
            int n = 0;
            for (Function cf : callerFns) {
                n++;
                log("--------------------------------------------------------");
                log("# Caller #" + n + ": " + cf.getName() + "@" + cf.getEntryPoint());
                log("--------------------------------------------------------");
                log(decompileFn(cf));
                log("");
                if (n >= 4) {
                    if (callerFns.size() > 4) log("(capped at 4 callers, " + (callerFns.size()-4) + " more)");
                    break;
                }
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
