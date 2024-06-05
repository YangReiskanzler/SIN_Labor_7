import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

public class AESFileEncryption {

    public static void main(String[] args) {
        // check if the generateKey command is used
        if (args.length == 2 && args[0].equals("generateKey")) {
            String keyFilePath = args[1];
            try {
                generateKey(keyFilePath);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;
        }

        // check if the correct number of arguments is provided
        if (args.length < 3) {
            System.out.println("Usage: java AESFileEncryption <input file> <key file> <output file>");
            return;
        }

        String inputFile = args[0];
        String keyFile = args[1];
        String outputFile = args[2];

        try {
            // read plaintext from input file
            byte[] inputFileBytes = Files.readAllBytes(Paths.get(inputFile));
            String inputText = new String(inputFileBytes);

            // read AES key from key file
            byte[] keyFileBytes = Files.readAllBytes(Paths.get(keyFile));
            SecretKey secretKey = new SecretKeySpec(keyFileBytes, "AES");

            // encrypt the input text
            String encryptedText = encrypt(inputText, secretKey);

            // write the encrypted text to the output file
            try (FileWriter fileWriter = new FileWriter(outputFile)) {
                fileWriter.write(encryptedText);
            }

            System.out.println("Datei erfolgreich verschlüsselt und gespeichert: " + outputFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // method to encrypt a plaintext using AES
    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // method to generate an AES key and save it to a file
    public static void generateKey(String keyFilePath) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] keyBytes = secretKey.getEncoded();
        try (FileOutputStream keyFileOutputStream = new FileOutputStream(keyFilePath)) {
            keyFileOutputStream.write(keyBytes);
        }
        System.out.println("Schlüssel erfolgreich generiert und gespeichert: " + keyFilePath);
    }
}
