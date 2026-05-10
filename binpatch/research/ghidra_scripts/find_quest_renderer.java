// find_quest_renderer.java
//
// Two parallel searches for the quest-log description renderer:
//
// (A) String search inside the exe for class names like "CQuestWindow",
//     "CMissionWindow", "CNotebook", "CDiary", "Quest", "Mission" etc.
//     The previous renderer (FUN_140215400) had "CMessageWindow::ConvertMessage"
//     debug string. Quest UI likely has a similar one. We chase XREFs to
//     each match.
//
// (B) Byte-level wider hunt for "byte >= 0x80 -> skip" gates that the
//     previous CMP+JNC scan missed:
//        TEST <reg8>, <reg8> ; JS  ...     (signed-bit jump)
//        CMP  <reg>, 0xE0   ; JB  ...     (SJIS-lead-only acceptance, halfwidth excluded)
//        CMP  <reg>, 0xA0   ; JB/JAE      (explicit halfwidth boundary)
//
// For each find, decompile the containing function. Among the results
// we expect to find ONE where the loop has no halfwidth path and skips
// halfwidth bytes silently — that's our culprit.
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

public class find_quest_renderer extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;
    Map<Address, List<Address>> insRefMap = new HashMap<>(); // addr -> list of instruction addresses

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_quest_renderer.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Quest renderer hunt");
        log("===========================================================");
        log("");

        // ========== pre-build: every instruction's referenced addresses ==========
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

        // ========== PART A: string search ==========
        log("############################################################");
        log("# PART A — class-name strings in exe");
        log("############################################################");
        log("");

        String[] needles = {
            "CQuestWindow", "CMissionWindow", "CNotebookWindow", "CMessageWindow",
            "CQuest", "CMission", "CNotebook", "CDiary",
            "Quest", "Mission", "Notebook",
            "ConvertMessage", "ConvertText", "ConvertString",
            "::Convert",
        };
        Set<Function> stringHitFns = new LinkedHashSet<>();
        for (String n : needles) {
            log("# string '" + n + "':");
            List<Address> addrs = findStringInProgram(n);
            if (addrs.isEmpty()) { log("  (not found)"); log(""); continue; }
            for (Address sa : addrs) {
                List<Address> refs = insRefMap.get(sa);
                if (refs == null || refs.isEmpty()) {
                    log("  string @ " + sa + "  (no instr refs)");
                    continue;
                }
                for (Address ra : refs) {
                    Function fn = getFunctionContaining(ra);
                    String fname = (fn != null) ? fn.getName() + "@" + fn.getEntryPoint() : "(none)";
                    log("  string @ " + sa + "  ref " + ra + "  in " + fname);
                    if (fn != null) stringHitFns.add(fn);
                }
            }
            log("");
        }
        log("# Distinct fns from strings: " + stringHitFns.size());
        log("");

        // ========== PART B: byte-pattern hunt ==========
        log("############################################################");
        log("# PART B — byte-pattern hunt for byte>=0x80 skip-gates");
        log("############################################################");
        log("");

        // Walk every instruction; detect (TEST reg8, reg8) followed by JS,
        // and (CMP reg8, 0xE0) followed by JB/JC.
        Map<Function, List<Address>> testJs = new LinkedHashMap<>();
        Map<Function, List<Address>> cmpE0Jb = new LinkedHashMap<>();
        Map<Function, List<Address>> cmpA0Jb = new LinkedHashMap<>();

        InstructionIterator it = listing.getInstructions(true);
        Instruction prev = null;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            if (prev != null) {
                String pm = prev.getMnemonicString();
                String cm = ins.getMnemonicString();

                // TEST <r8>,<r8> ; JS
                if (pm.equals("TEST") && cm.equals("JS")) {
                    String op0 = prev.getDefaultOperandRepresentation(0).toUpperCase();
                    String op1 = prev.getDefaultOperandRepresentation(1).toUpperCase();
                    if (op0.equals(op1) && (op0.endsWith("L") || op0.endsWith("H") || op0.matches("R\\d+B"))) {
                        Function fn = getFunctionContaining(prev.getAddress());
                        if (fn != null) testJs.computeIfAbsent(fn, k -> new ArrayList<>()).add(prev.getAddress());
                    }
                }
                // CMP <r8>, 0xE0 ; JB/JC
                if (pm.equals("CMP") && (cm.equals("JC") || cm.equals("JB") || cm.equals("JNAE"))) {
                    if (prev.getNumOperands() >= 2) {
                        Object[] objs = prev.getOpObjects(1);
                        if (objs != null) {
                            for (Object o : objs) {
                                if (o instanceof Scalar) {
                                    long v = ((Scalar) o).getUnsignedValue();
                                    String op0 = prev.getDefaultOperandRepresentation(0).toUpperCase();
                                    if (op0.endsWith("L") || op0.matches("R\\d+B")) {
                                        if (v == 0xE0) {
                                            Function fn = getFunctionContaining(prev.getAddress());
                                            if (fn != null) cmpE0Jb.computeIfAbsent(fn, k -> new ArrayList<>()).add(prev.getAddress());
                                        }
                                        if (v == 0xA0) {
                                            Function fn = getFunctionContaining(prev.getAddress());
                                            if (fn != null) cmpA0Jb.computeIfAbsent(fn, k -> new ArrayList<>()).add(prev.getAddress());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            prev = ins;
        }

        log("## TEST <r8>,<r8> ; JS  (sites: " + sumLists(testJs) + ", fns: " + testJs.size() + ")");
        for (Map.Entry<Function, List<Address>> e : testJs.entrySet()) {
            log("  " + e.getKey().getName() + "@" + e.getKey().getEntryPoint() +
                " count=" + e.getValue().size());
        }
        log("");

        log("## CMP <r8>, 0xE0 ; JB/JC  (sites: " + sumLists(cmpE0Jb) + ", fns: " + cmpE0Jb.size() + ")");
        for (Map.Entry<Function, List<Address>> e : cmpE0Jb.entrySet()) {
            log("  " + e.getKey().getName() + "@" + e.getKey().getEntryPoint() +
                " count=" + e.getValue().size());
        }
        log("");

        log("## CMP <r8>, 0xA0 ; JB/JC  (sites: " + sumLists(cmpA0Jb) + ", fns: " + cmpA0Jb.size() + ")");
        for (Map.Entry<Function, List<Address>> e : cmpA0Jb.entrySet()) {
            log("  " + e.getKey().getName() + "@" + e.getKey().getEntryPoint() +
                " count=" + e.getValue().size());
        }
        log("");

        // ========== PART C: prioritized decompile ==========
        // Functions that appear in (string hits) AND (byte-pattern hits) are top priority.
        // Then string-only, then byte-pattern only.
        Set<Function> dump = new LinkedHashSet<>();
        for (Function f : stringHitFns) dump.add(f);
        for (Function f : testJs.keySet()) dump.add(f);
        for (Function f : cmpE0Jb.keySet()) dump.add(f);
        for (Function f : cmpA0Jb.keySet()) dump.add(f);

        // Skip the ones we already know
        Set<Long> skip = new HashSet<>(Arrays.asList(
            0x1401ce2b0L, 0x140215400L, 0x140212f40L, 0x14020e6b0L,
            0x1401e5270L, 0x140216720L, 0x1402873c0L, 0x140332ba0L,
            0x140078850L, 0x140078d00L, 0x140078fb0L, 0x1400794a0L,
            0x140079360L, 0x140077580L, 0x140078090L, 0x1400772c0L,
            0x1400776a0L, 0x140077420L, 0x140077ec0L,
            0x1400c3c70L, 0x1400c4540L, 0x1400c3a80L
        ));

        log("############################################################");
        log("# Decompiled NEW candidates (excluding already-analyzed)");
        log("############################################################");
        log("");
        int n = 0;
        for (Function fn : dump) {
            if (skip.contains(fn.getEntryPoint().getOffset())) continue;
            n++;
            log("================================================================");
            log("# #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 25) {
                log("(capped at 25 functions)");
                break;
            }
        }

        log("# DONE");
        out.close();
        println("DONE -> " + outPath);
    }

    int sumLists(Map<Function, List<Address>> m) {
        int s = 0;
        for (List<Address> l : m.values()) s += l.size();
        return s;
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
