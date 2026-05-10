// find_mbtowc_callers.java
//
// Find every code site that calls Windows API MultiByteToWideChar /
// WideCharToMultiByte / mbstowcs and dump containing function + context.
// One of these is almost certainly the quest-log description path —
// it converts the Russian halfwidth bytes through a CP_UTF8 / CP_ACP
// code page that doesn't accept them, producing the truncated output
// we see in the inventory side panel.
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

public class find_mbtowc_callers extends GhidraScript {

    PrintWriter out;
    DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String outPath = "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_mbtowc_callers.txt";
        out = new PrintWriter(new FileWriter(outPath));

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        log("===========================================================");
        log("# Find Windows API converter callers");
        log("===========================================================");
        log("");

        String[] symNames = {
            "MultiByteToWideChar", "WideCharToMultiByte",
            "mbstowcs", "mbstowcs_s", "mbsrtowcs", "_mbstowcs_l",
        };

        SymbolTable st = currentProgram.getSymbolTable();

        for (String sn : symNames) {
            log("###############################################");
            log("# Looking for symbol: " + sn);
            log("###############################################");
            // find any symbol matching that name
            SymbolIterator it = st.getSymbols(sn);
            List<Symbol> syms = new ArrayList<>();
            while (it.hasNext()) {
                Symbol s = it.next();
                syms.add(s);
                log("  symbol @ " + s.getAddress() + " (type=" + s.getSymbolType() + ", source=" + s.getSource() + ")");
            }
            if (syms.isEmpty()) {
                log("  (no symbol)");
                log("");
                continue;
            }

            // collect every reference to those symbols
            Set<Function> callers = new LinkedHashSet<>();
            for (Symbol s : syms) {
                ReferenceIterator refIt = currentProgram.getReferenceManager().getReferencesTo(s.getAddress());
                while (refIt.hasNext()) {
                    Reference r = refIt.next();
                    Address from = r.getFromAddress();
                    Function fn = getFunctionContaining(from);
                    String fname = (fn != null) ? fn.getName() + "@" + fn.getEntryPoint() : "(no func)";
                    log("  ref " + from + "  type=" + r.getReferenceType() + "  in " + fname);
                    if (fn != null) callers.add(fn);
                }
            }
            log("");
            log("# Distinct callers: " + callers.size());
            log("");

            // decompile each
            int n = 0;
            for (Function fn : callers) {
                n++;
                log("================================================================");
                log("# Caller #" + n + ": " + fn.getName() + "@" + fn.getEntryPoint());
                log("================================================================");
                log(decompileFn(fn));
                log("");
                if (n >= 12) {
                    log("(capped at 12)");
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
