package com.bpce.webapi.extensions.cert.util;

import com.vordel.circuit.Message;
import com.vordel.trace.Trace;

public class CertificatesProxyInvoke {

    public static boolean invoke(final Message msg) {

        final String keyType = (String) msg.get("apigtw.cert.keytype");
        final String keyValue = (String) msg.get("apigtw.cert.keyvalue");

        try {

            final CertDetails certDetails = CertificatesFactory.getCertificate(keyType, keyValue);
            assert certDetails != null;

            msg.put("apigtw.cert.certdetails", certDetails);

            return true;

        } catch (Exception e) {
            msg.put("apigtw.cert.msg.failure", e.getMessage());
            Trace.error(e);
            return false;
        }
    }

}
