// find_preview_truncators.java
//
// Find functions that truncate strings to a max char count and write ".."
// at the end (the "Расс.." pattern from quest log previews).
//
// Strategy:
//   A) find data refs to string ".." (0x2E 0x2E 0x00) — used as ellipsis marker
//   B) find functions with TWO consecutive `MOV byte ptr [...], 0x2E` writes
//      — those write ".." inline
//   C) find truncate-style functions: byte loop + counter + ASCII gate +
//      no halfwidth handling
//
// Also dump:
//   - FUN_14002a4b0 (HW_SHIFT but big, 48 CALLS — possibly partial halfwidth)
//   - FUN_140315150 (quest UI region, was in known list)
//   - FUN_140216720 (width calculator — for halfwidth pattern reference)
//   - FUN_1402873c0 (notebook text formatter)
//   - FUN_140332ba0 (message text formatter)
//
//@category TrailsFromZero
//@runtime Java

import java.io.PrintWriter;
import java.io.FileWriter;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_preview_truncators extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_truncators.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Preview/truncate functions");
        log("===========================================================");
        log("");

        // ===== PASS A: find references to ".." string in data section =====
        log("############################################################");
        log("# A) Functions referencing \"..\" string (ellipsis marker)");
        log("############################################################");
        log("");
        Memory mem = currentProgram.getMemory();
        Set<Function> refsToDots = new LinkedHashSet<>();
        // Scan rdata: 0x14039_0000..0x14048_0000 typical
        long scanStart = 0x140300000L;
        long scanEnd   = 0x140500000L;
        Address scanA = toAddr(scanStart);
        Address scanAEnd = toAddr(scanEnd);
        while (scanA != null && scanA.compareTo(scanAEnd) < 0) {
            try {
                byte b0 = mem.getByte(scanA);
                if (b0 == 0x2E) {
                    byte b1 = mem.getByte(scanA.add(1));
                    if (b1 == 0x2E) {
                        byte b2 = mem.getByte(scanA.add(2));
                        // ".."  + null-terminated single-byte string OR followed by quote/space
                        if (b2 == 0x00 || b2 == 0x2E) {
                            // record this address as candidate
                            ReferenceIterator refIt = currentProgram.getReferenceManager().getReferencesTo(scanA);
                            int count = 0;
                            while (refIt.hasNext() && count < 50) {
                                Reference r = refIt.next();
                                Address from = r.getFromAddress();
                                Function fn = getFunctionContaining(from);
                                if (fn != null) {
                                    refsToDots.add(fn);
                                    log("  \"..\" @ " + scanA + " <- " + fn.getName() + "@" + fn.getEntryPoint() +
                                        " (instr " + from + ")");
                                }
                                count++;
                            }
                        }
                    }
                }
            } catch (Exception ex) { /* not initialized memory */ }
            scanA = scanA.add(1);
            if (monitor.isCancelled()) break;
        }
        log("# Distinct functions referencing \"..\": " + refsToDots.size());
        log("");

        // ===== PASS B: find functions with two consecutive MOV byte,0x2E =====
        log("############################################################");
        log("# B) Functions writing inline \"..\" (2x MOV byte ptr [...], 0x2E)");
        log("############################################################");
        log("");
        Set<Function> inlineDotWriters = new LinkedHashSet<>();

        // ===== Main scan pass =====
        // Per-function stats:
        //   [0] ASCII gate (CMP 0x80 / TEST+JS / CMP 0x7F)
        //   [1] newline gate (CMP byte,0x0A or 0x0D)
        //   [2] halfwidth CMP (0xA0/0xA1/0xC0/0xDE/0xDF)
        //   [3] halfwidth shift (LEA/ADD/SUB +0x60/+0x5F)
        //   [4] CMP byte,0x40 (paired with shift)
        //   [5] byte stores
        //   [6] CALL count
        //   [7] SJIS pair gate
        //   [8] small length CMPs (0x10..0x80) — counter limits
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
            int[] s = stats.computeIfAbsent(fn, k -> new int[9]);
            String mnem = ins.getMnemonicString();

            if (mnem.equals("CMP") && ins.getNumOperands() >= 2) {
                String op0 = ins.getDefaultOperandRepresentation(0).toUpperCase();
                if (op0.endsWith("L") || op0.matches("R\\d+B")) {
                    Object[] o1 = ins.getOpObjects(1);
                    if (o1 != null) for (Object o : o1) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            if (v == 0x80 || v == 0x7F) s[0]++;
                            if (v == 0x0A || v == 0x0D) s[1]++;
                            if (v == 0xA0 || v == 0xA1 || v == 0xC0 || v == 0xDE || v == 0xDF) s[2]++;
                            if (v == 0x40) s[4]++;
                            if (v == 0x81 || v == 0x9F || v == 0xE0 || v == 0xFC) s[7]++;
                        }
                    }
                }
                // Also count CMP for register sizes — small length limits
                Object[] o1full = ins.getOpObjects(1);
                if (o1full != null) for (Object o : o1full) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        // small length-like values
                        if (v == 0x10 || v == 0x18 || v == 0x20 || v == 0x28 || v == 0x30 ||
                            v == 0x40 || v == 0x50 || v == 0x60) s[8]++;
                    }
                }
            }
            if (prev != null && prev.getMnemonicString().equals("TEST") && mnem.equals("JS")) {
                String op0 = prev.getDefaultOperandRepresentation(0).toUpperCase();
                String op1 = prev.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.equals(op1) && (op0.endsWith("L") || op0.matches("R\\d+B"))) {
                    s[0]++;
                }
            }
            if ((mnem.equals("LEA") || mnem.equals("ADD") || mnem.equals("SUB")) &&
                ins.getNumOperands() >= 2) {
                Object[] o1 = ins.getOpObjects(1);
                if (o1 != null) for (Object o : o1) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x60 || v == 0x5F) s[3]++;
                    }
                }
            }
            if (mnem.equals("MOV") && ins.getNumOperands() >= 2) {
                String op0 = ins.getDefaultOperandRepresentation(0);
                String op1 = ins.getDefaultOperandRepresentation(1).toUpperCase();
                if (op0.startsWith("byte ptr") && (op1.endsWith("L") || op1.matches("R\\d+B"))) {
                    s[5]++;
                }
                // Detect inline ".." write: MOV byte ptr [...], 0x2E
                if (op0.startsWith("byte ptr")) {
                    Object[] o1 = ins.getOpObjects(1);
                    if (o1 != null) for (Object o : o1) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            if (v == 0x2E) {
                                inlineDotWriters.add(fn);
                            }
                        }
                    }
                }
            }
            // MOV [reg], 0x2E2E (word) — inline ".." write
            if (mnem.equals("MOV") && ins.getNumOperands() >= 2) {
                String op0 = ins.getDefaultOperandRepresentation(0);
                if (op0.startsWith("word ptr") || op0.startsWith("dword ptr")) {
                    Object[] o1 = ins.getOpObjects(1);
                    if (o1 != null) for (Object o : o1) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue();
                            if (v == 0x2E2E || v == 0x2E2E2E || v == 0x2E2E2E2E) {
                                inlineDotWriters.add(fn);
                            }
                        }
                    }
                }
            }
            if (mnem.equals("CALL")) s[6]++;
            prev = ins;
        }
        log("Scanned " + ic + " instructions across " + stats.size() + " functions.");
        log("");

        // Print inline-dot-writers (PASS B result)
        log("# Functions with inline \"..\" write (MOV byte/word, 0x2E or 0x2E2E):");
        for (Function fn : inlineDotWriters) {
            int[] s = stats.get(fn);
            if (s == null) continue;
            log("  " + fn.getName() + "@" + fn.getEntryPoint() +
                "  ASCII=" + s[0] + " HW=" + s[2] + " SHIFT=" + s[3] +
                " STORES=" + s[5] + " CALLS=" + s[6]);
        }
        log("# Total: " + inlineDotWriters.size());
        log("");

        // Decompile dot-writers / dot-referencers that lack halfwidth handling
        log("############################################################");
        log("# Decompiled dot-writers (inline) WITHOUT halfwidth handling");
        log("############################################################");
        log("");
        Set<Function> hotDotWriters = new LinkedHashSet<>();
        for (Function fn : inlineDotWriters) {
            int[] s = stats.get(fn);
            if (s == null) continue;
            if (s[2] > 0) continue;
            if (s[3] > 0 && s[4] > 0) continue;
            // need an ASCII gate or byte stream
            if (s[0] == 0 && s[5] == 0) continue;
            hotDotWriters.add(fn);
        }
        int dn = 0;
        for (Function fn : hotDotWriters) {
            dn++;
            int[] s = stats.get(fn);
            log("================================================================");
            log("# Dot-writer #" + dn + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                "  ASCII=" + s[0] + " HW=" + s[2] + " SHIFT=" + s[3] +
                " STORES=" + s[5] + " CALLS=" + s[6]);
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (dn >= 8) {
                log("(capped at 8)");
                break;
            }
        }

        // Also decompile up to 4 dot-string referencers (pass A)
        log("############################################################");
        log("# Decompiled \"..\" string referencers (up to 4)");
        log("############################################################");
        log("");
        int rn = 0;
        for (Function fn : refsToDots) {
            rn++;
            log("================================================================");
            log("# Dot-ref #" + rn + ": " + fn.getName() + "@" + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (rn >= 4) break;
        }


        // Filter: ASCII gate >= 1 AND (newline gate OR small length limit) AND byte stores >= 1
        // AND halfwidth direct == 0 AND (shift==0 OR cmp40==0)
        // AND function NOT in path/CRT range (skip <0x140070000 or 0x140068000..0x14014c000 path range)
        log("############################################################");
        log("# Truncate/preview candidates");
        log("# Filter: ASCII>0 AND (NL>0 OR small_len>=2) AND STORES>0");
        log("#         AND no halfwidth handling");
        log("############################################################");
        log("");

        List<Function> candidates = new ArrayList<>();
        for (Map.Entry<Function, int[]> e : stats.entrySet()) {
            int[] s = e.getValue();
            Function fn = e.getKey();
            long ea = fn.getEntryPoint().getOffset();

            if (s[0] == 0) continue;                    // need ASCII gate
            if (s[1] == 0 && s[8] < 2) continue;        // need newline OR length limits
            if (s[5] == 0) continue;                    // need byte stores
            if (s[2] > 0) continue;                     // skip halfwidth-aware (direct)
            if (s[3] > 0 && s[4] > 0) continue;         // skip halfwidth-aware (shift+cmp40)

            // Skip very early addresses (likely CRT/STL/path utils)
            if (ea < 0x140070000L) continue;
            // Skip our known file/path-handler range
            if (ea >= 0x140068000L && ea < 0x14006b000L) continue;
            if (ea == 0x14014b150L) continue;

            candidates.add(fn);
        }

        candidates.sort((a, b) -> {
            int[] sa = stats.get(a); int[] sb = stats.get(b);
            int wa = sa[0] * 2 + sa[1] * 3 + sa[5] + sa[6] / 5 + sa[8];
            int wb = sb[0] * 2 + sb[1] * 3 + sb[5] + sb[6] / 5 + sb[8];
            return wb - wa;
        });

        log(String.format("%-38s  %s", "function", "ASCII NL HW SHIFT CMP40 STORES CALLS SJIS LEN"));
        for (Function fn : candidates) {
            int[] s = stats.get(fn);
            log(String.format("%-38s  %5d %2d %2d %5d %5d %6d %5d %4d %3d",
                fn.getName() + "@" + fn.getEntryPoint(),
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8]));
        }
        log("");
        log("# Total candidates: " + candidates.size());
        log("");

        // Decompile top 12 candidates
        log("############################################################");
        log("# Decompiled top 12 candidates");
        log("############################################################");
        log("");
        int n = 0;
        for (Function fn : candidates) {
            n++;
            int[] s = stats.get(fn);
            log("================================================================");
            log("# #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint() +
                "  ASCII=" + s[0] + " NL=" + s[1] + " HW=" + s[2] +
                " SHIFT=" + s[3] + " CMP40=" + s[4] +
                " STORES=" + s[5] + " CALLS=" + s[6] + " SJIS=" + s[7] +
                " LEN=" + s[8]);
            log("================================================================");
            log(decompileFn(fn));
            log("");
            if (n >= 12) {
                log("(capped at 12)");
                break;
            }
        }

        // Targeted dumps
        long[] targets = {
            0x14002a4b0L,  // HW_SHIFT but big, 48 CALLS — partial halfwidth?
            0x140315150L,  // quest UI region, was in known
            0x140216720L,  // width calculator (halfwidth-aware reference)
            0x1402873c0L,  // notebook text formatter
            0x140332ba0L,  // message text formatter
        };
        log("############################################################");
        log("# Targeted dumps");
        log("############################################################");
        log("");
        for (long ea : targets) {
            Function fn = getFunctionAt(toAddr(ea));
            if (fn == null) {
                log("# (no function at " + Long.toHexString(ea) + ")");
                continue;
            }
            int[] s = stats.get(fn);
            log("================================================================");
            log("# Target: " + fn.getName() + "@" + fn.getEntryPoint() +
                (s != null ? "  ASCII=" + s[0] + " NL=" + s[1] + " HW=" + s[2] +
                             " SHIFT=" + s[3] + " CMP40=" + s[4] +
                             " STORES=" + s[5] + " CALLS=" + s[6] + " SJIS=" + s[7]
                           : ""));
            log("================================================================");
            log(decompileFn(fn));
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
