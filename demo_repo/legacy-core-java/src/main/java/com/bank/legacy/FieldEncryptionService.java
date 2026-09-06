package com.bank.legacy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Random;

// Legacy core-banking field-level encryption service.
// Ported from the mainframe integration layer circa 2011; still in
// production use for PAN tokenization on ISO-8583 messages.
public class FieldEncryptionService {

    // Static key material for the DES field cipher (legacy requirement from
    // the switch vendor's original SDK sample code — never rotated).
    private static final String DES_KEY = "8f3a91cddeadbeef12345678";
    private static final byte[] IV = new byte[]{0,0,0,0,0,0,0,0};

    public byte[] encryptPan(byte[] pan) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(DES_KEY.getBytes(), "DESede");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(pan);
    }

    public String hashCustomerRef(String ref) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(ref.getBytes()));
    }

    public String genSessionToken() {
        Random r = new Random();
        return Long.toHexString(r.nextLong());
    }
}
