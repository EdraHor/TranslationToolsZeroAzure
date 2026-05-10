// find_all_p3_gates.java
//
// Find ALL occurrences of the exact P3-style narrow-gate signature in the exe:
//   LEA EAX, [<reg> - 0x20]   ; 8D <ModRM> <disp8=0xE0>
//   CMP AL, 0x5F              ; 3C 5F
//   JA  <short>               ; 77 <imm8>  (or  JNC: 73 <imm8>)
//
// Also check JNZ (75) variant, but P3 uses JA (77).
//
// For each hit, report:
//   - Address of CMP immediate (the byte to patch: imm = ip+1)
//   - Containing function entry
//   - Whether function is already known halfwidth-aware
//
// We already know:
//   P3 = 0x14028caa5  (in FUN_14028b700)
//   P4 candidate = 0x14028b2b3  (in FUN_14028aac0)
//   P5 candidate = 0x14028a443  (in FUN_140289a30)
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
import ghidra.program.model.scalar.Scalar;

public class find_all_p3_gates extends GhidraScript {

    PrintWriter out;

    static final Set<Long> KNOWN_HW_AWARE_OUTER = new HashSet<>(Arrays.asList(
        0x14028b700L, 0x14028aac0L, 0x140289a30L, 0x140287b50L,
        0x140212f40L, 0x140215400L, 0x14020e6b0L, 0x140215190L,
        0x1401e5270L, 0x1401e60d0L,
        0x140077580L, 0x140078090L, 0x140078d00L, 0x140078fb0L
    ));

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_all_p3_gates.txt";
        out = new PrintWriter(new FileWriter(outPath));

        log("===========================================================");
        log("# All P3-style narrow gates: LEA -0x20; CMP AL,0x5F; JA");
        log("===========================================================");
        log("");

        // Iterate all instructions in code blocks (.text)
        Memory mem = currentProgram.getMemory();
        Listing list = currentProgram.getListing();

        log(String.format("%-15s %-15s %-22s %s",
            "CMP_addr", "patch_byte", "function", "status"));

        int hits = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isExecute()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            InstructionIterator it = list.getInstructions(
                currentProgram.getAddressFactory().getAddressSet(start, end), true);

            // Slide-window of 3 last instructions
            Instruction[] win = new Instruction[3];
            int idx = 0;
            while (it.hasNext()) {
                win[idx % 3] = it.next();
                idx++;
                if (idx < 3) continue;
                Instruction i0 = win[(idx - 3) % 3];
                Instruction i1 = win[(idx - 2) % 3];
                Instruction i2 = win[(idx - 1) % 3];
                if (i0 == null || i1 == null || i2 == null) continue;

                // i0: LEA <reg32>, [<reg>+(-0x20)]
                if (!i0.getMnemonicString().equals("LEA")) continue;
                String op0_1 = i0.toString().toLowerCase();
                if (!op0_1.contains("-0x20")) continue;

                // i1: CMP AL, 0x5F
                if (!i1.getMnemonicString().equals("CMP")) continue;
                String op1_str = i1.getDefaultOperandRepresentation(0);
                if (!op1_str.equals("AL")) continue;
                Object[] ops1 = i1.getOpObjects(1);
                boolean isFiveF = false;
                for (Object o : ops1) {
                    if (o instanceof Scalar && ((Scalar)o).getUnsignedValue() == 0x5F) {
                        isFiveF = true; break;
                    }
                }
                if (!isFiveF) continue;

                // i2: JA / JNC / JNZ to forward target
                String mnem2 = i2.getMnemonicString();
                if (!mnem2.equals("JA") && !mnem2.equals("JNC") && !mnem2.equals("JNZ")) continue;

                // Found a hit
                Address cmpAddr = i1.getAddress();
                Address patchAddr = cmpAddr.add(1);  // imm byte after opcode 3C

                Function fn = getFunctionContaining(cmpAddr);
                String fnName = (fn == null) ? "?" : "FUN_" + Long.toHexString(fn.getEntryPoint().getOffset());
                String status = (fn != null && KNOWN_HW_AWARE_OUTER.contains(fn.getEntryPoint().getOffset()))
                    ? "OUTER_HW_AWARE" : "outer-?";
                if (fn != null && fn.getEntryPoint().getOffset() == 0x14028b700L)
                    status = "P3 (already patched)";
                if (fn != null && fn.getEntryPoint().getOffset() == 0x14028aac0L)
                    status = "P4 candidate";
                if (fn != null && fn.getEntryPoint().getOffset() == 0x140289a30L)
                    status = "P5 candidate";

                log(String.format("%-15s %-15s %-22s %s  (jump=%s)",
                    cmpAddr.toString(), patchAddr.toString(), fnName, status, mnem2));
                hits++;
            }
        }

        log("");
        log("# Total P3-style gates found: " + hits);
        log("# DONE");
        out.flush();
        out.close();
        println("Wrote " + outPath);
    }

    void log(String s) {
        out.println(s);
        println(s);
    }
}
