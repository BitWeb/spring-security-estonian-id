package ee.bitweb.springframework.security.estonianid.authentication;

import ee.sk.smartid.*;
import ee.sk.smartid.exception.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationService extends EstonianIdAuthenticationService implements InitializingBean {

    public static final String ERR_INVALID_PARAMETERS = "INVALID_PARAMETERS";
    public static final String ERR_USER_ACCOUNT_NOT_FOUND = "USER_ACCOUNT_NOT_FOUND";
    public static final String ERR_REQUEST_FORBIDDEN = "REQUEST_FORBIDDEN";
    public static final String ERR_USER_REFUSED = "USER_REFUSED";
    public static final String ERR_SESSION_TIMEOUT = "SESSION_TIMEOUT";
    public static final String ERR_DOCUMENT_UNUSABLE = "DOCUMENT_UNUSABLE";
    public static final String ERR_TECHNICAL_ERROR = "TECHNICAL_ERROR";
    public static final String ERR_CLIENT_NOT_SUPPORTED = "CLIENT_NOT_SUPPORTED";
    public static final String ERR_SERVER_MAINTENANCE = "SERVER_MAINTENANCE";

    private static final Map<Class<? extends SmartIdException>, String> errorCodeMapping = 
            new HashMap<Class<? extends SmartIdException>, String>();

    @Value("classpath:TEST_of_EID-SK_2016.pem.crt")
    private Resource testEidCert;

    @Value("classpath:TEST_of_NQ-SK_2016.pem.crt")
    private Resource testNqCert;

    private SmartIdClient smartIdClient;

    private AuthenticationResponseValidator responseValidator = new AuthenticationResponseValidator();

    private boolean trustTestCertificates;

    private String displayText = "Spring Security Smart-ID login";


    static {
        errorCodeMapping.put(InvalidParametersException.class, ERR_INVALID_PARAMETERS);
        errorCodeMapping.put(UserAccountNotFoundException.class, ERR_USER_ACCOUNT_NOT_FOUND);
        errorCodeMapping.put(RequestForbiddenException.class, ERR_REQUEST_FORBIDDEN);
        errorCodeMapping.put(UserRefusedException.class, ERR_USER_REFUSED);
        errorCodeMapping.put(SessionTimeoutException.class, ERR_SESSION_TIMEOUT);
        errorCodeMapping.put(DocumentUnusableException.class, ERR_DOCUMENT_UNUSABLE);
        errorCodeMapping.put(TechnicalErrorException.class, ERR_TECHNICAL_ERROR);
        errorCodeMapping.put(ClientNotSupportedException.class, ERR_CLIENT_NOT_SUPPORTED);
        errorCodeMapping.put(ServerMaintenanceException.class, ERR_SERVER_MAINTENANCE);
    }

    public SmartIdAuthenticationService(boolean trustTestCertificates) {
        this.trustTestCertificates = trustTestCertificates;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(smartIdClient, "smartIdClient must be specified");

        if (trustTestCertificates) {
            try {
                trustTestCertificates();
            } catch (Exception e) {
                logger.error("Could not add test certificates to trusted certificates list", e);
            }
        }
    }
    
    public SmartIdAuthenticationSession beginAuthentication(String userIdCode, 
                                                            SmartIdAuthenticationSession.CountryCode countryCode) {
        SmartIdAuthenticationSession authenticationSession = new SmartIdAuthenticationSession();

        if (ObjectUtils.isEmpty(userIdCode) || ObjectUtils.isEmpty(countryCode)
                || !SmartIdCredentialsValidator.validate(countryCode, userIdCode)) {
            authenticationSession.setStatus(SmartIdAuthenticationSession.AuthenticationStatus.ERROR);
            authenticationSession.setErrorCode(ERR_INVALID_PARAMETERS);
            return authenticationSession;
        }

        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash(HashType.SHA512);
        authenticationSession.setUserIdCode(userIdCode);
        authenticationSession.setCountryCode(countryCode);
        authenticationSession.setAuthenticationHash(authenticationHash);
        authenticationSession.setVerificationCode(authenticationHash.calculateVerificationCode());
        authenticationSession.setStartTime(new Date());
        authenticationSession.setStatus(SmartIdAuthenticationSession.AuthenticationStatus.PENDING);

        return authenticationSession;
    }


    public SmartIdAuthenticationSession validate(SmartIdAuthenticationSession authSession) throws Exception {
        SmartIdAuthenticationResponse response;

        try {
            response = smartIdClient.createAuthentication()
                    .withAuthenticationHash(authSession.getAuthenticationHash())
                    .withCountryCode(authSession.getCountryCode().name())
                    .withNationalIdentityNumber(authSession.getUserIdCode())
                    .withDisplayText(displayText)
                    .authenticate();
        } catch (Exception e) {
            authenticationFailure(authSession, null, e);

            if (!(e instanceof SmartIdException)) {
                logger.error(String.format("Unexpected exception on validating session for country '%s' and identity " +
                        "number '%s'", authSession.getCountryCode(), authSession.getUserIdCode()), e);
                throw e;
            }

            return authSession;
        }

        SmartIdAuthenticationResult result = responseValidator.validate(response);
        if (result.isValid()) {
            authenticationSuccess(authSession, response, result);
        } else {
            authenticationFailure(authSession, result, null);
        }

        return authSession;
    }

    private void trustTestCertificates() throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        this.responseValidator.addTrustedCACertificate((X509Certificate) certificateFactory.generateCertificate(testEidCert.getInputStream()));
        this.responseValidator.addTrustedCACertificate((X509Certificate) certificateFactory.generateCertificate(testNqCert.getInputStream()));
    }

    private void authenticationSuccess(SmartIdAuthenticationSession session, SmartIdAuthenticationResponse response,
                                       SmartIdAuthenticationResult result) {
        AuthenticationIdentity identity = result.getAuthenticationIdentity();

        session.setGivenName(identity.getGivenName());
        session.setSurName(identity.getSurName());
        session.setCertificate(response.getCertificate());
        session.setStatus(SmartIdAuthenticationSession.AuthenticationStatus.USER_AUTHENTICATED);
    }

    private void authenticationFailure(SmartIdAuthenticationSession session, SmartIdAuthenticationResult result,
                                       Exception e) {
        session.setStatus(SmartIdAuthenticationSession.AuthenticationStatus.ERROR);

        if (e instanceof SmartIdException) {
            session.setErrorCode(errorCodeMapping.get(e.getClass()));
        } else {
            session.setErrorCode(ERR_TECHNICAL_ERROR);
        }

        if (result != null && !ObjectUtils.isEmpty(result.getErrors())) {
            logger.info(String.format("Smart-ID authentication failure for country '%s' and identity number '%s', errors: %s",
                    session.getCountryCode(), session.getUserIdCode(), StringUtils.join(result.getErrors(), ", ")));
        }
    }

    public void setTestEidCert(Resource testEidCert) {
        this.testEidCert = testEidCert;
    }

    public void setTestNqCert(Resource testNqCert) {
        this.testNqCert = testNqCert;
    }

    public void setSmartIdClient(SmartIdClient smartIdClient) {
        this.smartIdClient = smartIdClient;
    }

    public AuthenticationResponseValidator getResponseValidator() {
        return responseValidator;
    }

    public void setResponseValidator(AuthenticationResponseValidator responseValidator) {
        this.responseValidator = responseValidator;
    }

    public String getDisplayText() {
        return displayText;
    }

    public void setDisplayText(String displayText) {
        this.displayText = displayText;
    }
}
