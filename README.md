# Java File Encryption

A small command-line Java project that encrypts and decrypts files using **AES-256-GCM**. A password is converted into an encryption key with **PBKDF2-HMAC-SHA256**.

## Features

- Encrypts any file (text, PDF, image, etc.).
- Decrypts files using the same password.
- Uses a fresh random salt and nonce for each encryption.
- GCM authentication detects incorrect passwords and modified encrypted data.
- Password is entered in the terminal without being echoed.
- Does not overwrite an existing output file.

## Requirements

- Java 17 or later
- Maven 3.8+ (optional, for building)

## Build

```bash
mvn clean package
```

## Run

Run from a terminal (not an IDE output panel, because the app uses hidden password input):

```bash
java -cp target/classes com.example.encryptor.FileEncryptor encrypt sample.pdf sample.pdf.enc
java -cp target/classes com.example.encryptor.FileEncryptor decrypt sample.pdf.enc recovered.pdf
```

The program asks for the password. Use the exact same password to decrypt.

You can also compile without Maven:

```bash
javac -d out src/main/java/com/example/encryptor/FileEncryptor.java
java -cp out com.example.encryptor.FileEncryptor encrypt sample.txt sample.txt.enc
```

## Encrypted file format

The output contains a 4-byte format marker (`JFE1`), a 16-byte random salt, a 12-byte random GCM nonce, and the authenticated ciphertext.

## Security notes

- Choose a long, unique password. A weak password can still be guessed offline.
- Keep your password safe; there is no password recovery.
- Keep an unencrypted backup until you have verified that decryption works.
- This demo reads the entire file into memory, so it is best for small-to-medium files.
- Do not commit private files, passwords, or real encrypted personal data to GitHub.
- This is an educational portfolio project, not a replacement for a professionally audited encryption tool.
