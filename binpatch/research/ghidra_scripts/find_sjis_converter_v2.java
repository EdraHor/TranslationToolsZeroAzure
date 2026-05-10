// find_sjis_converter_v2.java
//
// v2 fixes:
//   - Part A: instead of relying on Ghidra's ReferenceManager (which is empty
//     for "sjisutf8" — auto-analysis didn't link the string), scan ALL
//     instructions and find any LEA / MOV that references the string address
//     via RIP-relative or absolute addressing.
//   - Part B.2: lower the decompile threshold to 3 magic bytes (we have no
//     functions with 5+ in this binary).
//   - Also chase the string "font.itf" and "ucs2jis" the same way to
//     cross-validate the loader pattern.
//   - Decompile every found loader candidate AND every consumer.
//
//@category TrailsFromZero
//@menupath Tools.Misc.find_sjis_converter_v2
//@runtime Java

import java.io.PrintWriter;
import java.io.FileWriter;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.Register;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_sjis_converter_v2 extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_sjis_converter_v2.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("=========================================================");
        log("# zero.exe SJIS converter / UTF-8 validator hunt v2");
        log("=========================================================");
        log("");

        // ============================================================
        // STEP 1: pre-scan ALL instructions, build a map of which
        //         addresses are referenced from where.
        // ============================================================
        log("# STEP 1 — instruction-level address-ref scan + magic-byte scan");
        log("");

        // (a) Map: target address -> list of instruction addresses that touch it
        Map<Address, List<Address>> addrToCallers = new HashMap<>();

        // (b) Map: function -> set of magic-bytes seen in CMP/SUB/AND
        int[] magic = {0x80, 0x81, 0x9F, 0xA0, 0xA1, 0xC0, 0xDF, 0xE0};
        Map<Function, Set<Integer>> magicHits = new HashMap<>();

        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);
        long instCount = 0;

        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            instCount++;
            String mnem = ins.getMnemonicString();

            // (a) collect any address referenced by this instruction
            int nOps = ins.getNumOperands();
            for (int i = 0; i < nOps; i++) {
                Object[] objs = ins.getOpObjects(i);
                if (objs == null) continue;
                for (Object o : objs) {
                    if (o instanceof Address) {
                        Address ta = (Address) o;
                        addrToCallers.computeIfAbsent(ta, k -> new ArrayList<>()).add(ins.getAddress());
                    }
                }
            }
            // For LEA/MOV with [RIP+disp], Ghidra stores the resolved target as a
            // Reference on the instruction. Also harvest those.
            Reference[] refs = ins.getReferencesFrom();
            for (Reference r : refs) {
                if (r.getReferenceType().isData()) {
                    addrToCallers.computeIfAbsent(r.getToAddress(), k -> new ArrayList<>()).add(ins.getAddress());
                }
            }

            // (b) magic-byte counter
            if (mnem.equals("CMP") || mnem.equals("SUB") || mnem.equals("AND")) {
                for (int i = 0; i < nOps; i++) {
                    Object[] objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            for (int m : magic) {
                                if (v == m) {
                                    Function fn = getFunctionContaining(ins.getAddress());
                                    if (fn != null) {
                                        magicHits.computeIfAbsent(fn, k -> new TreeSet<>()).add(m);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        log("Scanned " + instCount + " instructions.");
        log("Address-ref map size: " + addrToCallers.size());
        log("");

        // ============================================================
        // STEP 2: for each filename string, find loader via address-ref map
        // ============================================================
        String[] filenames = {"sjisutf8", "ucs2jis", "font.itf"};
        Set<Function> loaders = new LinkedHashSet<>();

        for (String fname : filenames) {
            log("# STEP 2 — string '" + fname + "' refs");
            List<Address> stringAddrs = findStringInProgram(fname);
            log("  found " + stringAddrs.size() + " string occurrences");
            for (Address sa : stringAddrs) {
                log("  string @ " + sa);
                List<Address> callers = addrToCallers.get(sa);
                if (callers == null || callers.isEmpty()) {
                    // Try one-off: maybe instruction sees address+1 etc.
                    log("    (no instruction-level refs)");
                    continue;
                }
                for (Address callerAddr : callers) {
                    Function fn = getFunctionContaining(callerAddr);
                    if (fn != null) {
                        log("    referenced from " + callerAddr + "  in  " + fn.getName() + "@" + fn.getEntryPoint());
                        loaders.add(fn);
                    } else {
                        log("    referenced from " + callerAddr + "  (no function)");
                    }
                }
            }
            log("");
        }

        log("# Distinct loader candidates: " + loaders.size());
        log("");

        // ============================================================
        // STEP 3: decompile each loader, harvest globals it writes to
        // ============================================================
        log("# STEP 3 — decompile loader candidates + collect globals");
        log("");

        Set<Address> rwGlobals = new LinkedHashSet<>();

        for (Function fn : loaders) {
            log("================================================================");
            log("# Loader: " + fn.getName() + " @ " + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            // Collect globals (writable memory) referenced from this function
            Set<Address> globalsTouched = collectDataRefsInFunction(fn);
            log("# globals touched by this loader:");
            for (Address g : globalsTouched) {
                MemoryBlock mb = currentProgram.getMemory().getBlock(g);
                String tag = "";
                if (mb != null) {
                    tag = " (" + mb.getName() + ", " + (mb.isWrite() ? "W" : "R") +
                          (mb.isInitialized() ? "init" : "uninit") + ")";
                }
                log("  " + g + tag);
                if (mb != null && mb.isWrite()) rwGlobals.add(g);
            }
            log("");
        }

        log("# Distinct RW globals: " + rwGlobals.size());
        log("");

        // ============================================================
        // STEP 4: For each RW global, find its consumers (xrefs)
        // ============================================================
        log("# STEP 4 — table consumers (decoder candidates)");
        log("");

        Set<Function> consumers = new LinkedHashSet<>();
        for (Address g : rwGlobals) {
            log("---- RW global @ " + g + " ----");
            List<Address> callers = addrToCallers.get(g);
            if (callers == null) {
                log("  (no instruction refs)");
                continue;
            }
            int n = 0;
            for (Address callerAddr : callers) {
                Function fn = getFunctionContaining(callerAddr);
                if (fn == null) continue;
                consumers.add(fn);
                if (n++ < 30) {
                    log("  ref " + callerAddr + " in " + fn.getName() + "@" + fn.getEntryPoint());
                }
            }
            if (n >= 30) log("  ... (" + (n-30) + " more)");
            log("");
        }
        // Loaders are also consumers of their own buffer; that's fine.
        consumers.removeAll(loaders);
        log("# Distinct *non-loader* consumers: " + consumers.size());
        log("");

        // ============================================================
        // STEP 5: cross-reference consumers with magic-byte hits
        // ============================================================
        log("# STEP 5 — consumers that ALSO contain SJIS/UTF-8 magic byte CMPs");
        log("# (these are almost certainly text decoders!)");
        log("");
        List<Function> highInterest = new ArrayList<>();
        for (Function c : consumers) {
            Set<Integer> bytes = magicHits.get(c);
            if (bytes != null && bytes.size() >= 2) {
                log("  *** " + c.getName() + "@" + c.getEntryPoint() +
                    "   magic bytes: " + formatBytes(bytes));
                highInterest.add(c);
            }
        }
        log("");
        log("# High-interest count: " + highInterest.size());
        log("");

        // ============================================================
        // STEP 6: decompile high-interest functions
        // ============================================================
        log("# STEP 6 — decompiled HIGH-INTEREST functions");
        log("");
        for (Function fn : highInterest) {
            log("================================================================");
            log("# HIGH-INTEREST: " + fn.getName() + " @ " + fn.getEntryPoint() +
                "   bytes=" + formatBytes(magicHits.get(fn)));
            log("================================================================");
            log(decompileFn(fn));
            log("");
        }

        // ============================================================
        // STEP 7: also dump TOP magic-byte functions even if not consumers
        // ============================================================
        log("# STEP 7 — all magic-byte functions, sorted by hit-count desc");
        log("");
        List<Map.Entry<Function, Set<Integer>>> sorted = new ArrayList<>(magicHits.entrySet());
        sorted.sort((a, b) -> b.getValue().size() - a.getValue().size());
        for (Map.Entry<Function, Set<Integer>> e : sorted) {
            if (e.getValue().size() < 3) break;
            Function fn = e.getKey();
            log("  " + e.getValue().size() + " bytes  " + fn.getName() +
                "@" + fn.getEntryPoint() + "  " + formatBytes(e.getValue()));
        }
        log("");

        log("# STEP 7.2 — decompile top-7 magic-byte functions (size >= 3)");
        log("");
        int dec = 0;
        for (Map.Entry<Function, Set<Integer>> e : sorted) {
            if (e.getValue().size() < 3) break;
            dec++;
            Function fn = e.getKey();
            log("================================================================");
            log("# Magic-byte top #" + dec + ": " + fn.getName() + " @ " +
                fn.getEntryPoint() + "   bytes=" + formatBytes(e.getValue()));
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (dec >= 7) break;
        }

        log("# DONE");
        out.close();
        println("DONE -> " + outPath);
    }

    String formatBytes(Set<Integer> bytes) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (int b : bytes) {
            if (!first) sb.append(",");
            sb.append(String.format(" 0x%02X", b));
            first = false;
        }
        sb.append(" }");
        return sb.toString();
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

    Set<Address> collectDataRefsInFunction(Function fn) {
        Set<Address> result = new LinkedHashSet<>();
        AddressSetView body = fn.getBody();
        for (Address a : body.getAddresses(true)) {
            Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(a);
            for (Reference r : refs) {
                if (r.getReferenceType().isData()) {
                    result.add(r.getToAddress());
                }
            }
            // Also walk operand objects (in case Ghidra didn't create a Reference)
            Instruction ins = currentProgram.getListing().getInstructionAt(a);
            if (ins != null) {
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    Object[] objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof Address) {
                            result.add((Address) o);
                        }
                    }
                }
            }
        }
        return result;
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
