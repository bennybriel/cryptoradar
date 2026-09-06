package com.bank.pqc;

import org.bouncycastle.pqc.jcajce.provider.mlkem.BCMLKEMPublicKey;
import java.security.KeyPairGenerator;

// Pilot hybrid key-exchange service for the new wallet-service, run
// alongside identity-service's existing RS256 JWKS during the transition.
public class HybridKeyExchange {
    public KeyPairGenerator getMlKemGenerator() throws Exception {
        return KeyPairGenerator.getInstance("ML-KEM-1024", "BCPQC");
    }

    public KeyPairGenerator getMlDsaGenerator() throws Exception {
        return KeyPairGenerator.getInstance("ML-DSA-65", "BCPQC");
    }
}
