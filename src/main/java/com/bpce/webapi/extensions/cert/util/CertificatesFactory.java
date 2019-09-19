package com.bpce.webapi.extensions.cert.util;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.lang.StringUtils;

import com.bpce.webapi.extensions.cert.util.CertDetails.CertSource;
import com.vordel.store.cert.CertStore;

public class CertificatesFactory {

    public static final String                          KEY_TYPE_SHA1FINGERPRINT = "sha1fingerprint";
    public static final String                          KEY_TYPE_X5TS            = "x5ts";
    public static final String                          KEY_TYPE_DN              = "dn";
    public static final String                          KEY_TYPE_ALIAS           = "alias";

    private static final Map<String, CertDetails>       CERTS_CACHE_BY_ALIAS;
    private static final Map<String, CertDetails>       CERTS_CACHE_BY_SHA1FINGERPRINT;
    private static final Map<String, CertDetails>       CERTS_CACHE_BY_DN;
    private static final Map<String, CertDetails>       CERTS_CACHE_BY_X5TS;

    private static final List<Map<String, CertDetails>> CACHE_LIST;

    private static final KeyStore                       JVM_KEY_STORE;

    private static final ReentrantLock                  LOCK                     = new ReentrantLock();

    private static boolean                              initialized              = false;

    private CertificatesFactory() {
    }

    static {

        CERTS_CACHE_BY_ALIAS = Collections.synchronizedMap(new HashMap<>());
        CERTS_CACHE_BY_SHA1FINGERPRINT = Collections.synchronizedMap(new HashMap<>());
        CERTS_CACHE_BY_DN = Collections.synchronizedMap(new HashMap<>());
        CERTS_CACHE_BY_X5TS = Collections.synchronizedMap(new HashMap<>());

        CACHE_LIST = Collections.unmodifiableList(Arrays.asList(CERTS_CACHE_BY_ALIAS, CERTS_CACHE_BY_SHA1FINGERPRINT,
                CERTS_CACHE_BY_DN, CERTS_CACHE_BY_X5TS));

        final String keystorePath = CertUtils.getJksPath();
        final char[] keystorePwd = CertUtils.getJksPassword();

        if (StringUtils.isBlank(keystorePath)) {
            throw new IllegalStateException("The keystore path is not defined yet into the instance file");
        }

        if (!Paths.get(keystorePath).toFile().isFile()) {
            throw new IllegalStateException("The keystore does not exist or is not a file --> " + keystorePath);
        }

        try (final InputStream in = new BufferedInputStream(new FileInputStream(keystorePath), 8192)) {

            JVM_KEY_STORE = KeyStore.getInstance("JKS");
            JVM_KEY_STORE.load(in, keystorePwd);

            populateCache();

        } catch (Exception e) {
            throw new IllegalStateException("Unable to initialize certificates cache : " + e.getMessage(), e);
        }
    }

    public static CertDetails getCertificate(final String keyType, final String keyValue)
            throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException {

        if (!initialized) {
            populateCache();
        }
        if (StringUtils.isBlank(keyValue)) {
            throw new IllegalArgumentException("The key value of the certificate to look for cannot be blank !");
        }

        switch (keyType) {
        case KEY_TYPE_ALIAS:
            return CERTS_CACHE_BY_ALIAS.get(keyValue);
        case KEY_TYPE_DN:
            return CERTS_CACHE_BY_DN.get(keyValue);
        case KEY_TYPE_X5TS:
            return CERTS_CACHE_BY_X5TS.get(keyValue);
        case KEY_TYPE_SHA1FINGERPRINT:
            return CERTS_CACHE_BY_SHA1FINGERPRINT.get(keyValue);
        default:
            throw new IllegalArgumentException(
                    "Unable to retrieve the certificate details from the specified [keyType, keyValue] --> [" + keyType + ", " + keyValue + "]");
        }
    }

    private static void populateCache()
            throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException {
        try {
            LOCK.lock();
            populateCacheFromJks();
            populateCacheFromVordelStore();
            initialized = true;
        } finally {
            LOCK.unlock();
        }
    }

    private static void populateCacheFromJks()
            throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException {
        populateCache(JVM_KEY_STORE, CertSource.JKS);
    }

    private static void populateCacheFromVordelStore()
            throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException {
        populateCache(CertStore.getInstance().getKeyStore(), CertSource.VORDEL);
    }

    private static void populateCache(final KeyStore keystore, final CertSource source)
            throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException {

        if (keystore != null) {
            final Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                final String alias = aliases.nextElement();
                final X509Certificate x509Certificate = (X509Certificate) keystore.getCertificate(alias);
                final CertDetails certDetails = new CertDetails(alias, source, x509Certificate);

                CERTS_CACHE_BY_ALIAS.putIfAbsent(alias, certDetails);
                CERTS_CACHE_BY_X5TS.putIfAbsent(certDetails.getX5t(), certDetails);
                // TODO: add cache for DNs & fingerprint
            }
        } else {
            throw new IllegalStateException("The keystore must no be null !");
        }
    }

    public static void clearCaches() {
        try {
            LOCK.lock();
            CACHE_LIST.stream().forEach(Map::clear);
            initialized = false;
        } finally {
            LOCK.unlock();
        }
    }
}
