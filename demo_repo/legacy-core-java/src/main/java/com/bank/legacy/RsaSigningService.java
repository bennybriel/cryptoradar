package com.bank.legacy;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;

// RSA-1024 message signing for interbank settlement files (NIBSS gateway).
public class RsaSigningService {
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    public byte[] sign(byte[] data, java.security.PrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }
}
