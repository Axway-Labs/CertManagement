package com.bpce.webapi.extensions.cert.util;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class CertDetails {

    private final String          alias;

    private final CertSource      source;

    private PrivateKey            privateKey;

    private PublicKey             publicKey;

    private final X509Certificate x509Certificate;

    private String                x5t;

    private String                x5t256;

    public CertDetails(final String alias, final CertSource source, final X509Certificate x509Certificate) {
        this.alias = alias;
        this.source = source;
        this.x509Certificate = x509Certificate;
    }

    public String getAlias() {
        return this.alias;
    }

    public CertSource getSource() {
        return this.source;
    }

    public PublicKey getPublicKey() {
        if (this.publicKey == null) {
            this.publicKey = CertUtils.getPublicKey(getX509Certificate());
        }
        return this.publicKey;
    }

    public PrivateKey getPrivateKey() {
        if (this.privateKey == null) {
            this.privateKey = CertUtils.getPrivateKey(getX509Certificate());
        }
        return this.privateKey;
    }

    public String getX5t() throws CertificateEncodingException, NoSuchAlgorithmException {
        if (this.x5t == null) {
            this.x5t = CertUtils.generateX5t(getX509Certificate());
        }
        return this.x5t;
    }

    public String getX5t256() throws CertificateEncodingException, NoSuchAlgorithmException {
        if (this.x5t256 == null) {
            this.x5t256 = CertUtils.generateX5t256(getX509Certificate());
        }
        return this.x5t256;
    }

    public X509Certificate getX509Certificate() {
        return this.x509Certificate;
    }

    public enum CertSource {
        JKS, VORDEL;
    }

    @Override
    public String toString() {
        return String.format("CertDetails [source=%s, privateKey=%s, publicKey=%s, x509Certificate=%s, x5t=%s, x5t256=%s]", source, privateKey, publicKey,
                x509Certificate, x5t, x5t256);
    }

}
