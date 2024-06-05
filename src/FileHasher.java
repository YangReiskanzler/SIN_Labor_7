import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;


public class FileHasher {
    // Main method to generate hashes for a file
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length != 1) {
            System.out.println("Usage: java FileHasher <input file>");
            return;
        }

        String inputFile = args[0];

        try {
            byte[] inputFileBytes = Files.readAllBytes(Paths.get(inputFile));

            // MD5
            String md5Hash = hash(inputFileBytes, "MD5");
            saveHashToFile(md5Hash, inputFile + ".md5");

            // SHA-3
            String sha3Hash = hash(inputFileBytes, "SHA3-256");
            saveHashToFile(sha3Hash, inputFile + ".sha3");

            // RIPEMD-160
            String ripemd160Hash = hash(inputFileBytes, "RIPEMD160");
            saveHashToFile(ripemd160Hash, inputFile + ".ripemd160");

            System.out.println("Hashes generated and saved successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // calculate the hash of a file and return it as a string
    public static String hash(byte[] data, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digest;
        if ("RIPEMD160".equalsIgnoreCase(algorithm)) {
            digest = MessageDigest.getInstance(algorithm, "BC"); // Specify Bouncy Castle provider for RIPEMD-160
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

    // save the hash to a file with the specified file path
    public static void saveHashToFile(String hash, String filePath) {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(hash);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
