import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class HashChecker {
    // Main method to check the hash of a file
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java HashChecker <input file> <hash file> <algorithm>");
            return;
        }

        String inputFile = args[0];
        String hashFile = args[1];
        String algorithm = args[2];

        try {
            Security.addProvider(new BouncyCastleProvider());
            // Read the input file and hash file
            byte[] inputFileBytes = Files.readAllBytes(Paths.get(inputFile));
            byte[] hashFileBytes = Files.readAllBytes(Paths.get(hashFile));
            String fileHash = new String(hashFileBytes).trim();
            // Calculate the hash of the input file
            String calculatedHash = hash(inputFileBytes, algorithm);
            // Compare the hash values
            if (fileHash.equalsIgnoreCase(calculatedHash)) {
                System.out.println("The hash values match.");
            } else {
                System.out.println("The hash values do not match.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // Calculate the hash of a file and return it as a string
    public static String hash(byte[] data, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digest;
        if ("RIPEMD160".equalsIgnoreCase(algorithm)) {
            digest = MessageDigest.getInstance("RIPEMD160", "BC"); // Specify Bouncy Castle provider for RIPEMD-160
        } else {
            digest = MessageDigest.getInstance(algorithm);
        }
        byte[] hashBytes = digest.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

