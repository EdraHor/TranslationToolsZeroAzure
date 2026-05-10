// find_jnc_inc_pattern.java
//
// Hunt for sibling buggy text-renderers that share the exact byte
// signature of FUN_1401ce2b0's halfwidth-skipping ASCII gate:
//
//   73 09       JNC short +9     ; if byte >= 0x80 -> skip
//   48 FF C7    INC RDI          ;   advance input pointer
//   ...         MOV [buf], CL    ;   write byte
//   ...         INC buf
//   ...         INC iVar         ; (always)
//
// We look for the 5-byte sequence "73 09 48 FF C7" which is the JNC
// followed by `INC RDI`. Anything that matches almost certainly has
// the same halfwidth-skip bug and can be patched with the same
// 73 09 -> 90 90 trick.
//
// Also: variants with different pointer registers
//    73 09 48 FF C6  (INC RSI)
//    73 09 49 FF C7  (INC R15) — uses REX.W
// Some compiler-emitted variants may differ in NOP padding etc.,
// but the fundamental "JNC short +9 over a 9-byte advance/write/inc
// micro-block" should be very rare outside of these renderers.
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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_jnc_inc_pattern extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_jnc_pattern.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Hunt for siblings of FUN_1401ce2b0's halfwidth-skip bug");
        log("# Looking for byte pattern: 73 09 <REX> FF <reg>");
        log("===========================================================");
        log("");

        // Patterns to search for (5 bytes each):
        //   73 09 48 FF C7   JNC +9 ; INC RDI
        //   73 09 48 FF C6   JNC +9 ; INC RSI
        //   73 09 49 FF C7   JNC +9 ; INC R15
        //   73 09 49 FF C6   JNC +9 ; INC R14
        //   73 09 48 FF C2   JNC +9 ; INC RDX
        //   73 09 48 FF C0   JNC +9 ; INC RAX
        byte[][] patterns = {
            {0x73, 0x09, 0x48, (byte)0xFF, (byte)0xC7},
            {0x73, 0x09, 0x48, (byte)0xFF, (byte)0xC6},
            {0x73, 0x09, 0x49, (byte)0xFF, (byte)0xC7},
            {0x73, 0x09, 0x49, (byte)0xFF, (byte)0xC6},
            {0x73, 0x09, 0x48, (byte)0xFF, (byte)0xC2},
            {0x73, 0x09, 0x48, (byte)0xFF, (byte)0xC0},
        };
        String[] labels = {
            "JNC +9 ; INC RDI",
            "JNC +9 ; INC RSI",
            "JNC +9 ; INC R15",
            "JNC +9 ; INC R14",
            "JNC +9 ; INC RDX",
            "JNC +9 ; INC RAX",
        };

        Memory mem = currentProgram.getMemory();
        Set<Function> hitFns = new LinkedHashSet<>();
        List<String> hitDescs = new ArrayList<>();

        for (int p = 0; p < patterns.length; p++) {
            byte[] pat = patterns[p];
            log("# Searching for " + labels[p] + " (" + bytesHex(pat) + ")");
            for (MemoryBlock mb : mem.getBlocks()) {
                if (!mb.isInitialized() || !mb.isExecute()) continue;
                Address found = mem.findBytes(mb.getStart(), mb.getEnd(), pat,
                        null, true, monitor);
                while (found != null && !monitor.isCancelled()) {
                    Function fn = getFunctionContaining(found);
                    String fname = (fn != null) ? fn.getName() + "@" + fn.getEntryPoint() : "(no func)";
                    log(String.format("  %s   %-22s   in %s", found, bytesHex(pat), fname));
                    if (fn != null) {
                        hitFns.add(fn);
                        hitDescs.add(found + " " + labels[p] + " in " + fname);
                    }
                    Address next = found.add(1);
                    if (next.compareTo(mb.getEnd()) >= 0) break;
                    found = mem.findBytes(next, mb.getEnd(), pat,
                            null, true, monitor);
                }
            }
            log("");
        }

        log("");
        log("===========================================================");
        log("# All distinct hit functions: " + hitFns.size());
        log("===========================================================");
        log("");

        // For each hit, check the preceding bytes to see if it's preceded
        // by a CMP <reg>, 0x80 (i.e. exactly the buggy gate).
        log("# Looking at the 4 bytes BEFORE each hit (should contain CMP <reg>, 0x80):");
        for (String d : hitDescs) {
            try {
                String addrStr = d.substring(0, d.indexOf(' '));
                Address a = currentProgram.getAddressFactory().getAddress(addrStr);
                Address prev = a.subtract(3);    // CMP CL, 0x80 = 80 F9 80 = 3 bytes
                byte[] prevBytes = new byte[3];
                mem.getBytes(prev, prevBytes);
                String hexp = bytesHex(prevBytes);
                String tag = "";
                if ((prevBytes[0] & 0xFF) == 0x80 && (prevBytes[2] & 0xFF) == 0x80) {
                    tag = "  *** EXACT MATCH (CMP <reg>, 0x80 just before JNC) ***";
                }
                log("  " + d + "   prev3=" + hexp + tag);
            } catch (Exception ex) {
                log("  " + d + "   (could not read prev bytes: " + ex.getMessage() + ")");
            }
        }
        log("");

        // ------ decompile each distinct function ------
        log("===========================================================");
        log("# Decompiled hit functions");
        log("===========================================================");
        log("");
        for (Function fn : hitFns) {
            // skip our known FUN_1401ce2b0
            if (fn.getEntryPoint().getOffset() == 0x1401ce2b0L) {
                log("================================================================");
                log("# " + fn.getName() + "@" + fn.getEntryPoint() + "   (already known, skipping)");
                log("================================================================");
                log("");
                continue;
            }
            log("================================================================");
            log("# " + fn.getName() + "@" + fn.getEntryPoint());
            log("================================================================");
            log(decompileFn(fn));
            log("");
        }

        log("# DONE");
        out.close();
        println("DONE -> " + outPath);
    }

    String bytesHex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02X ", x & 0xFF));
        return s.toString().trim();
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
