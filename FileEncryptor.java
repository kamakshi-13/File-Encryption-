package com.example.encryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Small command-line file encryptor using AES-256-GCM and PBKDF2.
 * Usage: java ... FileEncryptor <encrypt|decrypt> <input-file> <output-file>
 */
public class FileEncryptor {
    private static final byte[] MAGIC = {'J', 'F', 'E', '1'};
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int KEY_BITS = 256;
    private static final int ITERATIONS = 210_000;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    public static void main(String[] args) {
        if (args.length != 3 ||
                !(args[0].equalsIgnoreCase("encrypt") || args[0].equalsIgnoreCase("decrypt"))) {
            System.out.println("Usage: java FileEncryptor <encrypt|decrypt> <input-file> <output-file>");
            return;
        }

        Console console = System.console();
        if (console == null) {
            System.err.println("Run this program in a terminal so the password can be hidden.");
            return;
        }

        char[] password = console.readPassword("Password: ");
        if (password == null || password.length == 0) {
            System.err.println("Password cannot be empty.");
            return;
        }

        Path input = Path.of(args[1]);
        Path output = Path.of(args[2]);

        try {
            if (!Files.isRegularFile(input)) {
                throw new IOException("Input file does not exist or is not a regular file.");
            }
            if (input.toAbsolutePath().normalize().equals(output.toAbsolutePath().normalize())) {
                throw new IOException("Input and output paths must be different.");
            }

            byte[] inputBytes = Files.readAllBytes(input);
            byte[] result = args[0].equalsIgnoreCase("encrypt")
                    ? encrypt(inputBytes, password)
                    : decrypt(inputBytes, password);

            // Do not silently overwrite an existing file.
            if (Files.exists(output)) {
                throw new IOException("Output already exists. Choose a different output path.");
            }
            Files.write(output, result);
            System.out.println("Success. Output written to: " + output.toAbsolutePath());
        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Operation failed: " + e.getMessage());
            System.err.println("For decryption, check that the password and encrypted file are correct.");
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static byte[] encrypt(byte[] plaintext, char[] password)
            throws GeneralSecurityException {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(iv);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        byte[] ciphertext = cipher.doFinal(plaintext);

        return ByteBuffer.allocate(MAGIC.length + SALT_LENGTH + IV_LENGTH + ciphertext.length)
                .put(MAGIC).put(salt).put(iv).put(ciphertext).array();
    }

    private static byte[] decrypt(byte[] encrypted, char[] password)
            throws GeneralSecurityException, IOException {
        int headerLength = MAGIC.length + SALT_LENGTH + IV_LENGTH;
        if (encrypted.length < headerLength + TAG_BITS / 8) {
            throw new IOException("File is too short or has an invalid format.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("This file was not created by this encryptor or is damaged.");
        }

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        buffer.get(salt).get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        // GCM authenticates the encrypted data; a wrong password or tampering fails here.
        return cipher.doFinal(ciphertext);
    }

    private static SecretKey deriveKey(char[] password, byte[] salt)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(keyBytes, "AES");
            } finally {
                Arrays.fill(keyBytes, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }
}
