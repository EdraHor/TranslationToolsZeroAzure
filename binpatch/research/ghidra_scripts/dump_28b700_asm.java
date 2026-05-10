// dump_28b700_asm.java
// Dump assembly of FUN_14028b700 with focus on CMP byte,0x60 sites.
//@category TrailsFromZero
//@runtime Java

import java.io.PrintWriter;
import java.io.FileWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.Memory;

public class dump_28b700_asm extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_28b700_asm.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outPath));

        Function fn = getFunctionAt(toAddr(0x14028b700L));
        if (fn == null) {
            out.println("# FUN_14028b700 not found");
            out.close();
            return;
        }

        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        out.println("===========================================================");
        out.println("# FUN_14028b700 ASM dump — focus on CMP byte,0x60 sites");
        out.println("===========================================================");
        out.println("");

        // Pass 1: list ALL CMP byte_reg, 0x60 sites in this function
        out.println("############################################################");
        out.println("# All CMP <r8>, 0x60 sites in function");
        out.println("############################################################");
        for (Address a : fn.getBody().getAddresses(true)) {
            Instruction ins = listing.getInstructionAt(a);
            if (ins == null) continue;
            String mnem = ins.getMnemonicString();
            if (!mnem.equals("CMP")) continue;
            if (ins.getNumOperands() < 2) continue;
            String op0 = ins.getDefaultOperandRepresentation(0).toUpperCase();
            if (!(op0.endsWith("L") || op0.matches("R\\d+B"))) continue;
            Object[] o1 = ins.getOpObjects(1);
            if (o1 == null) continue;
            for (Object o : o1) {
                if (o instanceof Scalar) {
                    long v = ((Scalar) o).getUnsignedValue();
                    if (v == 0x60) {
                        // dump 16 bytes around
                        StringBuilder bytesBefore = new StringBuilder();
                        StringBuilder bytesAt = new StringBuilder();
                        StringBuilder bytesAfter = new StringBuilder();
                        try {
                            for (int i = -8; i < 0; i++) {
                                bytesBefore.append(String.format("%02X ", mem.getByte(a.add(i)) & 0xFF));
                            }
                            for (int i = 0; i < ins.getLength(); i++) {
                                bytesAt.append(String.format("%02X ", mem.getByte(a.add(i)) & 0xFF));
                            }
                            for (int i = ins.getLength(); i < ins.getLength() + 12; i++) {
                                bytesAfter.append(String.format("%02X ", mem.getByte(a.add(i)) & 0xFF));
                            }
                        } catch (Exception e) {}
                        out.println("  @ " + a + ":");
                        out.println("    instr  : " + ins);
                        out.println("    bytes  : " + bytesAt.toString().trim() + "  <<< CMP byte_reg,0x60");
                        out.println("    before : " + bytesBefore.toString().trim());
                        out.println("    after  : " + bytesAfter.toString().trim());
                        out.println("");
                    }
                }
            }
        }
        out.println("");

        // Pass 2: full ASM dump (capped at 4000 lines)
        out.println("############################################################");
        out.println("# Full ASM dump");
        out.println("############################################################");
        int lines = 0;
        for (Address a : fn.getBody().getAddresses(true)) {
            Instruction ins = listing.getInstructionAt(a);
            if (ins == null) continue;
            StringBuilder bytes = new StringBuilder();
            try {
                for (int i = 0; i < ins.getLength(); i++) {
                    bytes.append(String.format("%02X ", mem.getByte(a.add(i)) & 0xFF));
                }
            } catch (Exception e) {}
            out.println(String.format("%s   %-24s   %s",
                a.toString(), bytes.toString().trim(), ins.toString()));
            lines++;
            if (lines >= 4000) {
                out.println("(capped at 4000 lines)");
                break;
            }
        }

        out.println("# DONE");
        out.close();
        println("DONE -> " + outPath);
    }
}
