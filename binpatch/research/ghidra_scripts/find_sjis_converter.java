// find_sjis_converter.java
//
// Goal: locate the SJIS->UTF-8 converter / UTF-8 validator inside zero.exe.
//
// Strategy:
//   PART A — From the file name:
//     1. Find the string "sjisutf8" in the binary.
//     2. Walk DATA xrefs to locate the loader function (which calls fopen/fread).
//     3. In the loader, identify the global pointer where the buffer is stored
//        (heuristic: the function passes a global as fread destination, or
//         stores rax of malloc into a global).
//     4. Walk DATA xrefs to that global => every site that *uses* the table
//        (this is the converter / validator).
//
//   PART B — From byte-pattern signatures:
//     Search instructions that CMP with magic SJIS / UTF-8 boundary bytes
//     (0x80, 0x81, 0x9F, 0xA0, 0xA1, 0xC0, 0xDF, 0xE0). Functions that
//     contain *several* of these comparisons are very likely text decoders.
//
// All findings are written to out_sjis_converter.txt for offline review.
//
//@category TrailsFromZero
//@menupath Tools.Misc.find_sjis_converter
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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_sjis_converter extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_sjis_converter.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("=========================================================");
        log("# zero.exe SJIS->UTF-8 converter / UTF-8 validator hunt");
        log("# Program: " + currentProgram.getName());
        log("# Image base: " + currentProgram.getImageBase());
        log("=========================================================");
        log("");

        // ============================================================
        // PART A — find the loader via "sjisutf8" string
        // ============================================================
        log("############################################################");
        log("# PART A — locate loader from \"sjisutf8\" filename string");
        log("############################################################");
        log("");

        List<Address> stringAddrs = findStringInProgram("sjisutf8");
        log("Found " + stringAddrs.size() + " hits for 'sjisutf8':");
        for (Address sa : stringAddrs) {
            log("  string @ " + sa);
        }
        log("");

        Set<Function> loaders = new LinkedHashSet<>();
        for (Address sa : stringAddrs) {
            for (Reference ref : getReferencesTo(sa)) {
                Address fromAddr = ref.getFromAddress();
                Function fn = getFunctionContaining(fromAddr);
                String fname = (fn != null) ? fn.getName() + "@" + fn.getEntryPoint() : "(no func)";
                log("  xref " + fromAddr + "  type=" + ref.getReferenceType() + "  in " + fname);
                if (fn != null) loaders.add(fn);
            }
        }
        log("");
        log("Distinct loader candidates: " + loaders.size());
        log("");

        // ============================================================
        // For each loader, decompile and try to find the global where
        // the buffer is stored.  Then xref that global.
        // ============================================================
        Set<Address> tableGlobals = new LinkedHashSet<>();
        for (Function fn : loaders) {
            log("---- loader: " + fn.getName() + " @ " + fn.getEntryPoint() + " ----");
            String dec = decompileFn(fn);
            log(dec);
            log("");

            // Heuristic: find data references *out* of this function — those
            // pointing into RW data sections are likely globals.
            Set<Address> globalsTouched = collectDataRefsInFunction(fn);
            log("  globals touched: " + globalsTouched.size());
            for (Address g : globalsTouched) {
                MemoryBlock mb = currentProgram.getMemory().getBlock(g);
                if (mb != null && mb.isWrite()) {
                    log("    " + g + "  (block " + mb.getName() + ", " + (mb.isInitialized()?"init":"uninit") + ")");
                    tableGlobals.add(g);
                }
            }
            log("");
        }

        log("");
        log("Distinct RW globals from loaders: " + tableGlobals.size());
        log("");

        // ============================================================
        // For every candidate global, list all functions that read it.
        // ============================================================
        log("############################################################");
        log("# PART A.2 — XREFs from RW globals (consumers of the table)");
        log("############################################################");
        log("");

        Set<Function> consumers = new LinkedHashSet<>();
        for (Address g : tableGlobals) {
            log("---- global @ " + g + " ----");
            int n = 0;
            for (Reference ref : getReferencesTo(g)) {
                Address fromAddr = ref.getFromAddress();
                Function fn = getFunctionContaining(fromAddr);
                if (fn == null) continue;
                consumers.add(fn);
                if (n++ < 30) {
                    log("  xref " + fromAddr + "  in " + fn.getName() + "@" + fn.getEntryPoint());
                }
            }
            if (n > 30) log("  ... (" + (n-30) + " more)");
            log("");
        }

        log("");
        log("Distinct consumer functions: " + consumers.size());
        log("");

        // ============================================================
        // Decompile each consumer (cap to keep file readable)
        // ============================================================
        log("############################################################");
        log("# PART A.3 — decompiled consumer functions");
        log("############################################################");
        log("");

        int count = 0;
        for (Function fn : consumers) {
            count++;
            log("================================================================");
            log("# Consumer #" + count + ": " + fn.getName() + " @ " + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (count >= 12) {
                log("  (capped at 12 consumers — increase if needed)");
                break;
            }
        }

        // ============================================================
        // PART B — byte-pattern signatures (instruction-level)
        // ============================================================
        log("");
        log("############################################################");
        log("# PART B — instruction scan: comparisons with magic bytes");
        log("# (0x80,0x81,0x9F,0xA0,0xA1,0xC0,0xDF,0xE0)");
        log("# These are SJIS / UTF-8 boundary constants. Functions");
        log("# that contain >= 3 of these are very likely text decoders.");
        log("############################################################");
        log("");

        int[] magic = {0x80, 0x81, 0x9F, 0xA0, 0xA1, 0xC0, 0xDF, 0xE0};
        Map<Function, Set<Integer>> hits = new HashMap<>();

        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);
        long instCount = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            instCount++;
            String mnem = ins.getMnemonicString();
            if (!mnem.equals("CMP") && !mnem.equals("SUB") && !mnem.equals("AND")) continue;
            // Inspect every scalar operand
            int nOps = ins.getNumOperands();
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
                                    hits.computeIfAbsent(fn, k -> new TreeSet<>()).add(m);
                                }
                            }
                        }
                    }
                }
            }
        }
        log("Scanned " + instCount + " instructions.");
        log("");

        // Sort by hit-count desc, show top 30 with >= 3 magic bytes
        List<Map.Entry<Function, Set<Integer>>> sorted = new ArrayList<>(hits.entrySet());
        sorted.sort((a, b) -> b.getValue().size() - a.getValue().size());

        int shown = 0;
        for (Map.Entry<Function, Set<Integer>> e : sorted) {
            if (e.getValue().size() < 3) break;
            shown++;
            Function fn = e.getKey();
            StringBuilder bytes = new StringBuilder();
            for (int b : e.getValue()) bytes.append(String.format("0x%02X ", b));
            log("  " + e.getValue().size() + " distinct magic bytes  in  " +
                fn.getName() + "@" + fn.getEntryPoint() + "   {" + bytes.toString().trim() + "}");
            if (shown >= 30) {
                log("  ... (capped at 30 — see hits map for more)");
                break;
            }
        }
        log("");

        // Decompile top 5 of those
        log("############################################################");
        log("# PART B.2 — decompiled TOP-5 magic-byte functions");
        log("############################################################");
        log("");
        int dec = 0;
        for (Map.Entry<Function, Set<Integer>> e : sorted) {
            if (e.getValue().size() < 5) break;
            dec++;
            Function fn = e.getKey();
            log("================================================================");
            log("# Magic-byte top #" + dec + ": " + fn.getName() + " @ " +
                fn.getEntryPoint() + "   bytes=" + e.getValue());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (dec >= 5) break;
        }

        log("");
        log("# DONE");
        out.close();
        println("DONE -> " + outPath);
    }

    void log(String s) {
        out.println(s);
        // also echo to console for short messages
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
                    Address to = r.getToAddress();
                    MemoryBlock mb = currentProgram.getMemory().getBlock(to);
                    if (mb != null && mb.isInitialized() == false) {
                        // BSS-style — likely globals
                        result.add(to);
                    } else if (mb != null && mb.isWrite()) {
                        result.add(to);
                    }
                }
            }
        }
        return result;
    }

    List<Address> findStringInProgram(String needle) {
        List<Address> hits = new ArrayList<>();
        Memory mem = currentProgram.getMemory();
        byte[] needleBytes = needle.getBytes(); // ASCII
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
