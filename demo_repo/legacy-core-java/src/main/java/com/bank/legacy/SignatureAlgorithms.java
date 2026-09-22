package com.bank.legacy;

import java.security.Signature;
import java.security.KeyPair;

// Additional interbank settlement signing paths, added alongside the
// original RSA-1024 flow in RsaSigningService. These use Java's JCA
// convention of a single concatenated "<hash>with<algorithm>" token,
// which is the most common way a signature algorithm is actually named
// in real Java code — and previously went completely undetected.
public class SignatureAlgorithms {

    public byte[] signWithRsa(byte[] data, KeyPair kp) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        return sig.sign();
    }

    public byte[] signWithEcdsa(byte[] data, KeyPair kp) throws Exception {
        Signature sig = Signature.getInstance("SHA1withECDSA");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        return sig.sign();
    }
}
