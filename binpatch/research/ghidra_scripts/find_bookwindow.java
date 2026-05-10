// find_bookwindow.java
//
// Locate CBookWindow::ConvertMessage and CTerminalQuestWindow code
// via debug strings in zero.exe. The previous CMessageWindow handler
// (FUN_140215400) had a "CMessageWindow::ConvertMessage" debug log
// string. CBookWindow has the same — and it's almost certainly the
// quest/notebook description renderer.
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
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_bookwindow extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;
    Map<Address, List<Address>> insRefMap = new HashMap<>();

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_bookwindow.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // ===== Build addr -> instructions referencing it map =====
        Listing listing = currentProgram.getListing();
        InstructionIterator ait = listing.getInstructions(true);
        while (ait.hasNext() && !monitor.isCancelled()) {
            Instruction ins = ait.next();
            int n = ins.getNumOperands();
            for (int i = 0; i < n; i++) {
                Object[] objs = ins.getOpObjects(i);
                if (objs == null) continue;
                for (Object o : objs) {
                    if (o instanceof Address) {
                        Address ta = (Address) o;
                        insRefMap.computeIfAbsent(ta, k -> new ArrayList<>()).add(ins.getAddress());
                    }
                }
            }
            for (Reference r : ins.getReferencesFrom()) {
                if (r.getReferenceType().isData()) {
                    insRefMap.computeIfAbsent(r.getToAddress(), k -> new ArrayList<>()).add(ins.getAddress());
                }
            }
        }

        log("===========================================================");
        log("# Find CBookWindow / CTerminalQuestWindow handlers");
        log("===========================================================");
        log("");

        String[] needles = {
            "CBookWindow::ConvertMessage",
            "CBookWindow",
            "CTerminalQuestWindow",
            "CTerminalQuestMenu",
        };

        Set<Function> seen = new LinkedHashSet<>();

        for (String n : needles) {
            log("###############################################");
            log("# searching string: \"" + n + "\"");
            log("###############################################");
            List<Address> addrs = findStringInProgram(n);
            if (addrs.isEmpty()) { log("  (not found)"); log(""); continue; }
            for (Address sa : addrs) {
                log("  string @ " + sa);
                List<Address> refs = insRefMap.get(sa);
                if (refs == null || refs.isEmpty()) {
                    log("  (no instr refs)");
                    continue;
                }
                for (Address ra : refs) {
                    Function fn = getFunctionContaining(ra);
                    String fname = (fn != null) ? fn.getName() + "@" + fn.getEntryPoint() : "(none)";
                    log("  ref " + ra + "  in " + fname);
                    if (fn != null) seen.add(fn);
                }
            }
            log("");
        }

        log("# Distinct candidate functions: " + seen.size());
        log("");

        // For RTTI strings (e.g. ".?AVCBookWindow@@") the DATA reference
        // lives in the vtable, not in code — so insRefMap may not catch them.
        // Walk Ghidra's reference manager for those addresses too.
        log("############################################################");
        log("# Cross-checking via Ghidra ReferenceManager (catches RTTI/vtable)");
        log("############################################################");
        log("");
        for (String n : needles) {
            List<Address> addrs = findStringInProgram(n);
            for (Address sa : addrs) {
                ReferenceIterator refIt = currentProgram.getReferenceManager().getReferencesTo(sa);
                while (refIt.hasNext()) {
                    Reference r = refIt.next();
                    Address from = r.getFromAddress();
                    Function fn = getFunctionContaining(from);
                    if (fn != null) {
                        log("  string '" + n + "' refed from " + from +
                            "  in " + fn.getName() + "@" + fn.getEntryPoint());
                        seen.add(fn);
                    }
                }
            }
        }
        log("");

        log("# Total candidates after both passes: " + seen.size());
        log("");

        // Decompile each
        log("############################################################");
        log("# Decompiled candidates (excluding already-known)");
        log("############################################################");
        log("");

        Set<Long> skip = new HashSet<>(Arrays.asList(
            0x1401ce2b0L, 0x140215400L, 0x140212f40L, 0x14020e6b0L,
            0x140078850L, 0x140078d00L, 0x140078fb0L
        ));

        int n = 0;
        for (Function fn : seen) {
            n++;
            log("================================================================");
            log("# #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                (skip.contains(fn.getEntryPoint().getOffset()) ? "   (already known)" : ""));
            log("================================================================");
            if (skip.contains(fn.getEntryPoint().getOffset())) {
                log("  (decomp omitted - see other dumps)");
                log("");
                continue;
            }
            log(decompileFn(fn));
            log("");
            if (n >= 18) {
                log("(capped at 18)");
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

    List<Address> findStringInProgram(String needle) {
        List<Address> hits = new ArrayList<>();
        Memory mem = currentProgram.getMemory();
        byte[] needleBytes = needle.getBytes();
        for (MemoryBlock mb : mem.getBlocks()) {
            if (!mb.isInitialized() || !mb.isRead()) continue;
            try {
                Address found = mem.findBytes(mb.getStart(), mb.getEnd(), needleBytes,
                        null, true, monitor);
                while (found != null) {
                    hits.add(found);
                    Address next = found.add(1);
                    if (next.compareTo(mb.getEnd()) >= 0) break;
                    found = mem.findBytes(next, mb.getEnd(), needleBytes,
                            null, true, monitor);
                }
            } catch (Exception ignored) {}
        }
        return hits;
    }
}
