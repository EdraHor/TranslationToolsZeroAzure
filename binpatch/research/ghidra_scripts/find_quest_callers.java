// find_quest_callers.java
//
// FUN_140325b80 has the signature of "load quest text by ID into a side
// buffer" (it indexes param_1 + 0x1030 + ID*8). Whoever calls this
// function and then later reads the buffer is the quest renderer/format
// site. Same goes for adjacent quest-related functions. Dump everything
// nearby in the address range 0x140325000..0x140330000 — that's the
// quest UI module.
//
// We list:
//   - callers of FUN_140325b80, FUN_140325150, FUN_140325b80
//   - all functions in 0x140325000..0x140330000
//   - decompile them so we can read the loop with eyes
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

public class find_quest_callers extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_quest_callers.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Quest module hunt: callers of suspected quest text load fns");
        log("===========================================================");
        log("");

        long[] targets = { 0x140325b80L, 0x140325150L, 0x140315150L };

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
            for (Reference r : ins.getReferencesFrom()) {
                if (r.getReferenceType().isCall() || r.getReferenceType().isJump()) {
                    long ta = r.getToAddress().getOffset();
                    if (tset.contains(ta) && !callsTo.get(ta).contains(ins.getAddress())) {
                        callsTo.get(ta).add(ins.getAddress());
                    }
                }
            }
        }

        Set<Function> allCallers = new LinkedHashSet<>();
        for (long t : targets) {
            log("######################################################");
            log("# CALLERS of 0x" + Long.toHexString(t));
            log("######################################################");
            List<Address> sites = callsTo.get(t);
            log("# direct call sites: " + sites.size());
            for (Address sa : sites) {
                Function cf = getFunctionContaining(sa);
                String fname = (cf != null) ? cf.getName() + "@" + cf.getEntryPoint() : "(no func)";
                log("  CALL/JMP from " + sa + " in " + fname);
                if (cf != null) allCallers.add(cf);
            }
            log("");
        }

        log("# Distinct caller functions: " + allCallers.size());
        log("");

        // Decompile each caller
        log("############################################################");
        log("# Decompiled callers");
        log("############################################################");
        log("");
        int n = 0;
        for (Function fn : allCallers) {
            n++;
            log("================================================================");
            log("# Caller #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 16) {
                log("(capped at 16)");
                break;
            }
        }

        // List every function in the quest UI region 0x140310000..0x140340000
        log("");
        log("############################################################");
        log("# Functions in 0x140310000..0x140340000 (quest module guess)");
        log("############################################################");
        log("");
        FunctionIterator fnIt = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> regionFns = new ArrayList<>();
        while (fnIt.hasNext()) {
            Function fn = fnIt.next();
            long ea = fn.getEntryPoint().getOffset();
            if (ea >= 0x140310000L && ea <= 0x140340000L) {
                regionFns.add(fn);
            }
        }
        log("# count: " + regionFns.size());
        for (Function fn : regionFns) {
            log("  " + fn.getName() + "@" + fn.getEntryPoint() +
                "   size=" + fn.getBody().getNumAddresses());
        }
        log("");

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
