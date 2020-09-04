package com.metadium.did.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

public class DidECDSASigner extends ECDSASigner {
    private String did;
    private String kid;

    public DidECDSASigner(ECPrivateKey privateKey) throws JOSEException {
        super(privateKey);
    }

    public DidECDSASigner(PrivateKey privateKey, Curve curve) throws JOSEException {
        super(privateKey, curve);
    }

    public DidECDSASigner(ECKey ecJWK) throws JOSEException {
        super(ecJWK);
    }

    public String getDid() {
        return did;
    }

    public void setDid(String did) {
        this.did = did;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return null;
    }
}
