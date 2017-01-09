package ee.bitweb.springframework.security.estonianid.authentication;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.soap.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

/**
 * Created by taavisikk on 5/11/16.
 */
public class MobileIdAuthenticationService extends EstonianIdAuthenticationService implements InitializingBean {

    public static final String ST_OK = "OK";
    public static final String ST_OUTSTANDING_TRANSACTION = "OUTSTANDING_TRANSACTION";
    public static final String ST_USER_AUTHENTICATED = "USER_AUTHENTICATED";
    public static final String ST_NOT_VALID = "NOT_VALID";
    public static final String ST_EXPIRED_TRANSACTION = "EXPIRED_TRANSACTION";
    public static final String ST_USER_CANCEL = "USER_CANCEL";
    public static final String ST_MID_NOT_READY = "MID_NOT_READY";
    public static final String ST_PHONE_ABSENT = "PHONE_ABSENT";
    public static final String ST_SENDING_ERROR = "SENDING_ERROR";
    public static final String ST_SIM_ERROR = "SIM_ERROR";
    public static final String ST_INTERNAL_ERROR = "INTERNAL_ERROR";

    private String appServiceName;
    private String digiDocServiceUrl;

    private static final String DIGIDOCSERVICE_WSDL_URL = "http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl";
    private static final Collection<String> SUPPORTED_LANGUAGE_CODES = Arrays.asList("EST", "ENG", "RUS", "LIT");
    private static final Collection<String> VALID_STATUSES = Arrays.asList(ST_OUTSTANDING_TRANSACTION, ST_USER_AUTHENTICATED,
            ST_NOT_VALID, ST_EXPIRED_TRANSACTION, ST_USER_CANCEL, ST_MID_NOT_READY, ST_PHONE_ABSENT, ST_SENDING_ERROR,
            ST_SIM_ERROR, ST_INTERNAL_ERROR);
    private static final Collection<Integer> ERROR_CODES = Arrays.asList(100, 101, 102, 103, 200, 201, 202, 203, 300,
            301, 302, 303, 304, 305, 413, 503);

    public void afterPropertiesSet() {
        Assert.notNull(appServiceName, "appServiceName must be specified");
        Assert.notNull(digiDocServiceUrl, "digiDocServiceUrl must be specified");
    }

    public MobileIdAuthenticationSession beginAuthentication(String phoneNo, String languageCode) {
        MobileIdAuthenticationSession authenticationSession = new MobileIdAuthenticationSession();

        if (ObjectUtils.isEmpty(phoneNo)) {
            logger.warn("Missing phone number");
            authenticationSession.setErrorCode(-1);
            return authenticationSession;
        }
        if (!SUPPORTED_LANGUAGE_CODES.contains(languageCode)) {
            languageCode = "EST";
        }
        String challenge = generateChallenge();

        if (trustAllCertificates) {
            doTrustAllCertificates();
        }

        try {
            SOAPConnection soapConnection = getSoapConnection();

            SOAPMessage requestMessage = getAuthenticationMessage(phoneNo, languageCode, challenge);
            SOAPMessage response = soapConnection.call(requestMessage, digiDocServiceUrl);
            logResponse(response);

            if (trustAllCertificates) {
                resetHttpsUrlConnection();
            }

            SOAPBody responseBody = response.getSOAPBody();

            if (responseBody.hasFault()) {
                authenticationSession.setErrorCode(getSoapErrorCode(responseBody.getFault()));
            } else {
                Node authenticationResponse = responseBody.getFirstChild();
                NodeList parts = authenticationResponse.getChildNodes();

                String status = null;
                String sessCode = null;
                String challengeId = null;
                String userIdCode = null;
                String userGivenName = null;
                String userSurname = null;

                for (int i = 0; i < parts.getLength(); i++) {
                    Node part = parts.item(i);
                    if (part.getNodeName().equalsIgnoreCase("Status")) {
                        status = part.getTextContent();
                    } else if (part.getNodeName().equalsIgnoreCase("Sesscode")) {
                        sessCode = part.getTextContent();
                    } else if (part.getNodeName().equalsIgnoreCase("ChallengeID")) {
                        challengeId = part.getTextContent();
                    } else if (part.getNodeName().equalsIgnoreCase("UserIDCode")) {
                        userIdCode = part.getTextContent();
                    } else if (part.getNodeName().equalsIgnoreCase("UserGivenname")) {
                        userGivenName = part.getTextContent();
                    } else if (part.getNodeName().equalsIgnoreCase("UserSurname")) {
                        userSurname = part.getTextContent();
                    }
                }

                if (status != null && status.equalsIgnoreCase(ST_OK)) {
                    Date now = new Date();
                    authenticationSession.setSessionCode(sessCode);
                    authenticationSession.setChallengeId(challengeId);
                    authenticationSession.setUserIdCode(userIdCode);
                    authenticationSession.setUserGivenName(userGivenName);
                    authenticationSession.setUserSurname(userSurname);
                    authenticationSession.setTimeStarted(now);
                    authenticationSession.setTimePolled(now);
                    authenticationSession.setStatus(status);
                } else {
                    logger.warn("MobileAuthenticate returned an invalid status. Returned status: " + status);
                    authenticationSession.setErrorCode(-1);
                }
            }
        } catch (SOAPException e) {
            if (trustAllCertificates) {
                resetHttpsUrlConnection();
            }
            authenticationSession.setErrorCode(-1);

            logger.warn("Unknown SOAPException: ", e);
        }

        return authenticationSession;
    }

    public MobileIdAuthenticationSession poll(MobileIdAuthenticationSession authenticationSession) {
        if (authenticationSession.isValidForPolling()) {
            Date now = new Date();
            if ((now.getTime() - authenticationSession.getTimeStarted().getTime()) / 1000 > 240) {
                logger.warn("Trying to use an expired or invalid MobileIdAuthenticationSession");
            }
            Long secondsToWait = 5L;
            Date timePolled = authenticationSession.getTimePolled();

            if (authenticationSession.getStatus().equals(ST_OK)) {
                // It's the first poll
                secondsToWait = 20L;
            }
            if ((now.getTime() - timePolled.getTime()) / 1000 < secondsToWait) {
                logger.warn("Trying to poll too soon");
            }

            if (trustAllCertificates) {
                doTrustAllCertificates();
            }

            try {
                SOAPConnection soapConnection = getSoapConnection();

                SOAPMessage requestMessage = getPollMessage(authenticationSession.getSessionCode());
                SOAPMessage response = soapConnection.call(requestMessage, digiDocServiceUrl);
                logResponse(response);

                if (trustAllCertificates) {
                    resetHttpsUrlConnection();
                }

                authenticationSession.setTimePolled(now);

                SOAPBody responseBody = response.getSOAPBody();
                if (responseBody.hasFault()) {
                    authenticationSession.setErrorCode(getSoapErrorCode(responseBody.getFault()));
                } else {
                    Node statusResponse = responseBody.getFirstChild();
                    NodeList parts = statusResponse.getChildNodes();

                    String status = null;
                    for (int i = 0; i < parts.getLength(); i++) {
                        Node part = parts.item(i);
                        if (part.getNodeName().equalsIgnoreCase("Status")) {
                            status = part.getTextContent();
                        }
                    }
                    authenticationSession.setStatus(status);

                    if (!VALID_STATUSES.contains(status)) {
                        logger.warn("Unknown status returned from GetMobileAuthenticateStatus. Returned status: " +
                                status);
                    }
                }
            } catch (SOAPException e) {
                if (trustAllCertificates) {
                    resetHttpsUrlConnection();
                }
                logger.warn("Unknown SOAPException: ", e);
                authenticationSession.setErrorCode(-1);
            }
        } else {
            logger.warn("Trying to poll an invalid MobileIdAuthenticationSession");
        }

        return authenticationSession;
    }

    protected static String generateChallenge() {
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        while(sb.length() < 20) {
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.toString().substring(0, 20);
    }

    private SOAPConnection getSoapConnection() throws SOAPException {
        SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();

        return soapConnectionFactory.createConnection();
    }

    private SOAPMessage getAuthenticationMessage(String phoneNo, String languageCode, String challenge) throws SOAPException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage message = messageFactory.createMessage();
        SOAPPart part = message.getSOAPPart();
        SOAPEnvelope envelope = part.getEnvelope();
        SOAPBody body = envelope.getBody();

        envelope.addNamespaceDeclaration("ddoc", DIGIDOCSERVICE_WSDL_URL);

        SOAPElement authenticate = body.addChildElement("MobileAuthenticate", "ddoc");
        authenticate.addChildElement("PhoneNo")
                .addTextNode(phoneNo);
        authenticate.addChildElement("Language")
                .addTextNode(languageCode);
        authenticate.addChildElement("ServiceName")
                .addTextNode(appServiceName);
        authenticate.addChildElement("SPChallenge")
                .addTextNode(challenge);
        authenticate.addChildElement("MessagingMode")
                .addTextNode("asynchClientServer");

        MimeHeaders headers = message.getMimeHeaders();
        headers.addHeader("SOAPAction", getSoapAction("MobileAuthenticate"));

        message.saveChanges();

        // Debug request message
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            message.writeTo(bos);
            logger.debug("MobileAuthenticate request: " + System.lineSeparator() + bos.toString());
        } catch (IOException e) { }

        return message;
    }

    private SOAPMessage getPollMessage(String sessionCode) throws SOAPException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage message = messageFactory.createMessage();
        SOAPPart part = message.getSOAPPart();
        SOAPEnvelope envelope = part.getEnvelope();
        SOAPBody body = envelope.getBody();

        envelope.addNamespaceDeclaration("ddoc", DIGIDOCSERVICE_WSDL_URL);

        SOAPElement authenticateStatus = body.addChildElement("GetMobileAuthenticateStatus", "ddoc");
        authenticateStatus.addChildElement("Sesscode")
                .addTextNode(sessionCode);
        authenticateStatus.addChildElement("WaitSignature")
                .addTextNode("0");

        MimeHeaders headers = message.getMimeHeaders();
        headers.addHeader("SOAPAction", getSoapAction("GetMobileAuthenticateStatus"));

        message.saveChanges();

        // Debug request message
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            message.writeTo(bos);
            logger.debug("GetMobileAuthenticateStatus request: " + System.lineSeparator() + bos.toString());
        } catch (IOException e) { }

        return message;
    }

    protected static int getSoapErrorCode(SOAPFault fault) {
        Integer faultCode = Integer.parseInt(fault.getFaultString());
        if (ERROR_CODES.contains(faultCode)) {
            return faultCode;
        }
        return -1;
    }

    private String getSoapAction(String actionName) {
        StringBuilder builder = new StringBuilder(digiDocServiceUrl);
        if (!digiDocServiceUrl.endsWith("/")) {
            builder.append("/");
        }
        builder.append(actionName);

        return builder.toString();
    }

    public String getAppServiceName() {
        return appServiceName;
    }

    public void setAppServiceName(String appServiceName) {
        this.appServiceName = appServiceName;
    }

    public String getDigiDocServiceUrl() {
        return digiDocServiceUrl;
    }

    public void setDigiDocServiceUrl(String digiDocServiceUrl) {
        this.digiDocServiceUrl = digiDocServiceUrl;
    }
}
