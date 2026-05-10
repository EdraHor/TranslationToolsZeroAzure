// Find _dt file loaders by searching ASCII filename strings and following xrefs
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class find_dt_loaders extends GhidraScript {

    private static final String[] TARGETS = {
        "t_ittxt",
        "t_ittxt2",
        "t_book",
        "t_book00",
        "t_book01",
        "t_book02",
        "t_quest",
        "t_item",
        "t_item2",
        "t_magic",
        "t_shop",
        "t_name",
        "t_crfget",
        "t_quartz",
    };

    private static final String OUT_PATH =
        "E:\\ZEnvCloud\\Documents\\Проекты\\Trails From Zero Lozalization\\TrailsFromZeroLocalization\\BinPatch\\out_dt_loaders.txt";

    private List<Address> findAllStrings(String needle) throws Exception {
        // Search for needle followed by NUL terminator, ASCII bytes
        byte[] pattern = (needle + "\0").getBytes(StandardCharsets.US_ASCII);
        Memory mem = currentProgram.getMemory();

        List<Address> hits = new ArrayList<>();
        Address start = mem.getMinAddress();
        while (start != null) {
            Address found = mem.findBytes(start, pattern, null, true, monitor);
            if (found == null) break;
            hits.add(found);
            try {
                start = found.add(1);
            } catch (Exception e) {
                break;
            }
        }
        return hits;
    }

    private String fnName(Address addr) {
        if (addr == null) return "<null>";
        Function f = getFunctionContaining(addr);
        if (f == null) return "<no func>";
        return f.getName() + "@" + f.getEntryPoint();
    }

    @Override
    public void run() throws Exception {
        // FileOutputStream + OutputStreamWriter(UTF-8) — handles Cyrillic path on Windows
        try (PrintWriter w = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(OUT_PATH), StandardCharsets.UTF_8))) {

            w.println("=== _dt FILE LOADER HUNT ===");
            w.println("Program: " + currentProgram.getName());
            w.println();

            ReferenceManager refMgr = currentProgram.getReferenceManager();

            for (String needle : TARGETS) {
                w.println("---- search: '" + needle + "' ----");
                List<Address> hits = findAllStrings(needle);
                if (hits.isEmpty()) {
                    w.println("  (not found)");
                    w.println();
                    continue;
                }

                for (Address h : hits) {
                    w.println("  string @ " + h + ": '" + needle + "'");

                    int refCount = 0;
                    for (Reference r : refMgr.getReferencesTo(h)) {
                        Address src = r.getFromAddress();
                        w.println("    xref from " + src
                                + "  type=" + r.getReferenceType()
                                + "  in " + fnName(src));
                        refCount++;
                    }
                    if (refCount == 0) {
                        w.println("    (no xrefs)");
                    }
                }
                w.println();
            }

            w.println("=== END ===");
        }

        println("Written to: " + OUT_PATH);
    }
}
