package com.bpce.webapi.extensions.cert.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Base64.Encoder;

import com.bpce.webapi.extensions.cert.util.CertDetails.CertSource;
import com.vordel.security.cert.PersonalInfo;
import com.vordel.security.openssl.Certificate;
import com.vordel.store.cert.CertStore;

public class CertUtils {

    public static PublicKey getPublicKey(final X509Certificate x509Certificate) {

        return x509Certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKey(final X509Certificate x509Certificate) {

        return null; // TODO: implement !
    }

    public static PrivateKey findPrivateKey(final CertSource source, String alias, KeyStore keyStore)
            throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {

        PrivateKey privateKey = null;

        switch (source) {

        case JKS:
            privateKey = (PrivateKey) keyStore.getKey(alias, getJksPassword());
            break;

        case VORDEL:
            final PersonalInfo personalInfo = CertStore.getInstance().getPersonalInfoByAlias(alias);
            privateKey = personalInfo.privateKey;
            break;

        default:
            throw new IllegalStateException("The specified source is not supported -->" + source.toString());
        }

        return privateKey;
    }

    public static String getJksPath() {
        return System.getProperty("javax.net.ssl.keyStore");
    }

    public static char[] getJksPassword() {
        if (System.getProperty("javax.net.ssl.keyStorePassword") != null) {
            return System.getProperty("javax.net.ssl.keyStorePassword").toCharArray();
        } else {
            throw new IllegalStateException("The JKS password is not specified into the system properties !");
        }
    }

    public static String generateX5t(final X509Certificate x509Certificate)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        final String algorithm = "SHA-1";
        return commonGenerateX5t(x509Certificate, algorithm);
    }

    public static String generateX5t256(final X509Certificate x509Certificate)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        final String algorithm = "SHA-256";
        return commonGenerateX5t(x509Certificate, algorithm);
    }

    private static String commonGenerateX5t(final X509Certificate x509Certificate, final String algorithm)
            throws NoSuchAlgorithmException, CertificateEncodingException {

        try {
            final byte[] certEncoded = x509Certificate.getEncoded();

            final MessageDigest md = MessageDigest.getInstance(algorithm);

            byte[] digest = md.digest(certEncoded);

            Encoder base64Encoder = Base64.getEncoder();

            return base64Encoder.encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Mandatory Algorithm missing from JRE", e);
        }
    }

    public static Certificate getVordelCertificateFromX509(final X509Certificate x509Certificate)
            throws CertificateEncodingException, IOException {
        try (final ByteArrayInputStream in = new ByteArrayInputStream(x509Certificate.getEncoded())) {
            return new Certificate(in);
        }
    }

    // public static void main(String[] args) throws CertificateEncodingException,
    // KeyStoreException, NoSuchAlgorithmException {
    //
    // // String jksPath =
    // // "D:\\Donnees\\B0000205\\Dev\\Temp\\BAPIDST-1977\\testkeystore.jks";
    // // String jksPwd = "password";
    //
    // String certAlias = "fr.bpce.test.lamarche.denis";
    //
    // CertDetails certDetails1 = CertificatesFactory.getCertificate("alias",
    // certAlias);
    //
    // if (certDetails1 != null) {
    //
    // System.out.println("### Cert1 - Empreinte x5t : " + certDetails1.getX5t());
    // System.out.println("### Cert1 - Empreinte x5t256 : " +
    // certDetails1.getX5t256());
    // System.out.println("### Cert1 - Public Key : " +
    // certDetails1.getPublicKey());
    // System.out.println("### Cert1 - Private Key : " +
    // certDetails1.getPrivateKey());
    // System.out.println("### Cert1 - X509 Certificate : " +
    // certDetails1.getX509Certificate());
    //
    // X509Certificate x509Cert = certDetails1.getX509Certificate();
    // X500Principal x500Principal = x509Cert.getSubjectX500Principal();
    // System.out.println("### Cert1 - x500Principal Name = " +
    // x500Principal.getName());
    // System.out.println("### Cert1 - x500Principal Encoded = " +
    // x500Principal.getEncoded());
    //
    // } else {
    // System.out.println("Aucun certicat trouve pour l'alias " + certAlias);
    // }
    //
    // certAlias = "BAPI R7 JWT Fournisseur";
    //
    // CertDetails certDetails2 = CertificatesFactory.getCertificate("alias",
    // certAlias);
    //
    // if (certDetails2 != null) {
    //
    // System.out.println("### Cert2 - Empreinte x5t : " + certDetails2.getX5t());
    // System.out.println("### Cert2 - Empreinte x5t256 : " +
    // certDetails2.getX5t256());
    // System.out.println("### Cert2 - Public Key : " +
    // certDetails2.getPublicKey());
    // System.out.println("### Cert2 - Private Key : " +
    // certDetails2.getPrivateKey());
    // System.out.println("### Cert2 - X509 Certificate : " +
    // certDetails2.getX509Certificate());
    //
    // X509Certificate x509Cert = certDetails2.getX509Certificate();
    // X500Principal x500Principal = x509Cert.getSubjectX500Principal();
    // System.out.println("### Cert2 - x500Principal Name = " +
    // x500Principal.getName());
    // System.out.println("### Cert2 - x500Principal Encoded = " +
    // x500Principal.getEncoded());
    //
    // } else {
    // System.out.println("Aucun certicat trouve pour l'alias " + certAlias);
    // }
    // }

    // /**
    // *
    // * @param alias
    // * @param jksPath
    // * @param jksPassword
    // * @return CertDetails
    // */
    // public static CertDetails getCertificateDetails(String alias) {
    //
    // CertDetails certDetails = null;
    //
    // try {
    //
    // boolean isAliasWithPrivateKey = false;
    // KeyStore keyStore = getJvmKeystore();
    //
    // if (keyStore != null) {
    // X509Certificate certificate = certificateLookup(alias, keyStore);
    //
    // if (certificate != null) {
    //
    // certDetails = new CertDetails(certificate);
    //
    // certDetails.setPublicKey(certificate.getPublicKey());
    //
    // isAliasWithPrivateKey = keyStore.isKeyEntry(alias);
    //
    // if (isAliasWithPrivateKey) {
    //
    // KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
    // keyStore.getEntry(alias,
    // new KeyStore.PasswordProtection(jvmKeystorePwd.toCharArray()));
    //
    // PrivateKey myPrivateKey = pkEntry.getPrivateKey();
    // certDetails.setPrivateKey(myPrivateKey);
    // }
    //
    // }
    //
    // }
    //
    // } catch (KeyStoreException e) {
    // e.printStackTrace();
    // } catch (NoSuchAlgorithmException e) {
    // e.printStackTrace();
    // } catch (UnrecoverableEntryException e) {
    // e.printStackTrace();
    // }
    //
    // return certDetails;
    // }

    public static X509Certificate certificateLookup(String alias, KeyStore keyStore) {

        X509Certificate x509Cert = null;

        try {

            x509Cert = (X509Certificate) keyStore.getCertificate(alias);

            if (x509Cert == null) {

                x509Cert = getCertFromInternalKeystore(alias);
            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return x509Cert;

    }

    public static X509Certificate getCertFromInternalKeystore(String alias) {

        X509Certificate x509Cert = null;

        CertStore cs = CertStore.getInstance();
        PersonalInfo pi = cs.getPersonalInfoByAlias(alias);

        if (pi != null) {
            // Load certificate chain
            x509Cert = pi.certificate;
        }

        return x509Cert;
    }

}
