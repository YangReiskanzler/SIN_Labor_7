import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class AESFileDecryption {
    // Main method to decrypt a file
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java AESFileDecryption <input file> <key file> <output file>");
            return;
        }

        String inputFile = args[0];
        String keyFile = args[1];
        String outputFile = args[2];

        try {
            decryptFile(inputFile, keyFile, outputFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // Method to decrypt a file
    public static void decryptFile(String inputFile, String keyFile, String outputFile) throws Exception {
        // Read the encrypted text from the input file
        byte[] inputFileBytes = Files.readAllBytes(Paths.get(inputFile));
        String encryptedText = new String(inputFileBytes);
        // Read the AES key from the key file
        byte[] keyFileBytes = Files.readAllBytes(Paths.get(keyFile));
        SecretKey secretKey = new SecretKeySpec(keyFileBytes, "AES");
        // Decrypt the encrypted text
        String decryptedText = decrypt(encryptedText, secretKey);
        // Write the decrypted text to the output file
        try (FileWriter fileWriter = new FileWriter(outputFile)) {
            fileWriter.write(decryptedText);
        }

        System.out.println("File decrypted and saved successfully: " + outputFile);
    }
    // Method to decrypt a text using AES
    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}
