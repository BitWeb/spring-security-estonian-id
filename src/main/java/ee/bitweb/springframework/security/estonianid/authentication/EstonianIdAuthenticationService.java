package ee.bitweb.springframework.security.estonianid.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public abstract class EstonianIdAuthenticationService {

    protected boolean trustAllCertificates = false;

    protected final Log logger = LogFactory.getLog(getClass());

    private static final SSLSocketFactory defaultSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
    private static final HostnameVerifier defaultHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();

    protected void doTrustAllCertificates() {
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}
                        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                    }
            }, new SecureRandom());

            HostnameVerifier hostnameVerifier = new HostnameVerifier() {
                public boolean verify(String s, SSLSession sslSession) {
                    if (!s.equalsIgnoreCase(sslSession.getPeerHost())) {
                        logger.warn("URL host '" + s + "' is different to SSLSession host '" + sslSession.getPeerHost() + "'.");
                    }
                    return true;
                }
            };

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
        } catch (Exception e) {
            resetHttpsUrlConnection();
            logger.error("Trusting all certificates failed: ", e);
        }
    }

    protected static void resetHttpsUrlConnection() {
        HttpsURLConnection.setDefaultSSLSocketFactory(defaultSocketFactory);
        HttpsURLConnection.setDefaultHostnameVerifier(defaultHostnameVerifier);
    }

    public boolean getTrustAllCertificates() {
        return trustAllCertificates;
    }

    public void setTrustAllCertificates(boolean trustAllCertificates) {
        this.trustAllCertificates = trustAllCertificates;
    }
}
