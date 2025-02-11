import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.SecureRandom;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class AESExample {

    // Method to generate AES key (256 bits)
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Use 256-bit AES
        return keyGenerator.generateKey();
    }

    // Method to generate a random Initialization Vector (IV)
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Method to encrypt the message using AES with CBC mode
    public static String encrypt(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage); // Return Base64 encoded string
    }

    // Method to decrypt the message using AES with CBC mode
    public static String decrypt(String encryptedMessage, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedMessage = cipher.doFinal(decodedMessage);
        return new String(decryptedMessage); // Return the decrypted message as a string
    }

    public static void main(String[] args) {
        try {
            // Generate AES Key and IV
            SecretKey aesKey = generateAESKey();
            IvParameterSpec iv = generateIV();

            // Original message to be encrypted
            String message = "This is a confidential message!";
            System.out.println("Original Message: " + message);

            // Encrypt the message
            String encryptedMessage = encrypt(message, aesKey, iv);
            System.out.println("Encrypted Message (Base64): " + encryptedMessage);

            // Decrypt the message
            String decryptedMessage = decrypt(encryptedMessage, aesKey, iv);
            System.out.println("Decrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
