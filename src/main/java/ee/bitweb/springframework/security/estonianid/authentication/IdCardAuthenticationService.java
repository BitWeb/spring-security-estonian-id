package ee.bitweb.springframework.security.estonianid.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.w3c.dom.NodeList;

import javax.xml.bind.DatatypeConverter;
import javax.xml.soap.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Created by taavisikk on 5/11/16.
 */
public class IdCardAuthenticationService implements InitializingBean {

    public static final String ST_GOOD = "GOOD";
    public static final String ST_BAD_CERTIFICATE = "BAD_CERTIFICATE";
    public static final String ST_AUTHENTICATED = "AUTHENTICATED";

    private final Log logger = LogFactory.getLog(getClass());

    private String digiDocServiceUrl;

    private static final String DIGIDOCSERVICE_WSDL_URL = "http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl";

    public void afterPropertiesSet() {
        Assert.notNull(digiDocServiceUrl, "digiDocServiceUrl must be specified");
    }

    public String checkCertificate(X509Certificate certificate) {
        try {
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();

            SOAPMessage requestMessage = getRequestMessage(certificate);

            SOAPMessage response = soapConnection.call(requestMessage, digiDocServiceUrl);
            SOAPBody responseBody = response.getSOAPBody();
            if (responseBody.hasFault()) {
                logger.error("CheckCertificate fault: " + responseBody.getFault().getFaultString());
            } else {
                org.w3c.dom.Node checkCertificateResponse = responseBody.getFirstChild();
                NodeList parts = checkCertificateResponse.getChildNodes();

                String status = null;
                String userIdCode = null;

                for (int i = 0; i < parts.getLength(); i++) {
                    org.w3c.dom.Node part = parts.item(i);
                    if (part.getNodeName().equalsIgnoreCase("Status")) {
                        status = part.getTextContent();
                    } else if (part.getNodeName().equalsIgnoreCase("UserIDCode")) {
                        userIdCode = part.getTextContent();
                    }
                }
                if (status != null && status.equalsIgnoreCase(ST_GOOD)) {
                    return userIdCode;
                }
            }

        } catch (SOAPException e) {
            logger.error(e);
        } catch (CertificateEncodingException e) {
            logger.error(e);
        }
        return null;
    }

    private SOAPMessage getRequestMessage(X509Certificate certificate) throws SOAPException, CertificateEncodingException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage message = messageFactory.createMessage();
        SOAPPart part = message.getSOAPPart();
        SOAPEnvelope envelope = part.getEnvelope();
        SOAPBody body = envelope.getBody();

        envelope.addNamespaceDeclaration("ddoc", DIGIDOCSERVICE_WSDL_URL);

        SOAPElement checkCertificate = body.addChildElement("CheckCertificate", "ddoc");
        checkCertificate.addChildElement("Certificate")
                .addTextNode(DatatypeConverter.printBase64Binary(certificate.getEncoded()));

        MimeHeaders headers = message.getMimeHeaders();
        headers.addHeader("SOAPAction", getSoapAction("CheckCertificate"));

        message.saveChanges();

        // Debug request message
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            message.writeTo(bos);
            logger.debug("CheckCertificate request: " + System.lineSeparator() + bos.toString());
        } catch (IOException e) { }

        return message;
    }

    private String getSoapAction(String actionName) {
        StringBuilder builder = new StringBuilder(digiDocServiceUrl);
        if (!digiDocServiceUrl.endsWith("/")) {
            builder.append("/");
        }
        builder.append(actionName);

        return builder.toString();
    }

    public String getDigiDocServiceUrl() {
        return digiDocServiceUrl;
    }

    public void setDigiDocServiceUrl(String digiDocServiceUrl) {
        this.digiDocServiceUrl = digiDocServiceUrl;
    }
}
