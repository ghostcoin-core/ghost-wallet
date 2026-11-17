import java.nio.file.Path;
import java.util.HexFormat;

import pro.javacard.capfile.CAPFile;

/**
 * Prints the code hash of a CAP file: the SHA-256 of its load file data
 * block, the components in load order, which is what the card receives. The
 * zip around them (with its timestamps) is not hashed, so the same source
 * gives the same hash on every build. This hash goes into each card's
 * certificate.
 */
public final class CapHash {
    public static void main(String[] args) throws Exception {
        CAPFile cap = CAPFile.fromFile(Path.of(args[0]));
        System.out.println("code hash (SHA-256 of the load file data block): "
                + HexFormat.of().formatHex(cap.getLoadFileDataHash("SHA-256")));
    }
}
