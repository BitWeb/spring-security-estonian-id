package ee.bitweb.springframework.security.estonianid.authentication;

import ee.sk.smartid.AuthenticationHash;
import org.springframework.util.ObjectUtils;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationSession {

    private String userIdCode;

    private String givenName;

    private String surName;

    private CountryCode countryCode;

    private AuthenticationHash authenticationHash;

    private String verificationCode;

    private Date startTime;

    private AuthenticationStatus status;

    private X509Certificate certificate;

    private String errorCode;

    public boolean isAuthenticated() {
        return this.status == AuthenticationStatus.USER_AUTHENTICATED;
    }

    public boolean isPending() {
        return ObjectUtils.isEmpty(errorCode) && this.status == AuthenticationStatus.PENDING;
    }

    public String getUserIdCode() {
        return userIdCode;
    }

    public void setUserIdCode(String userIdCode) {
        this.userIdCode = userIdCode;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getSurName() {
        return surName;
    }

    public void setSurName(String surName) {
        this.surName = surName;
    }

    public CountryCode getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(CountryCode countryCode) {
        this.countryCode = countryCode;
    }

    public AuthenticationHash getAuthenticationHash() {
        return authenticationHash;
    }

    public void setAuthenticationHash(AuthenticationHash authenticationHash) {
        this.authenticationHash = authenticationHash;
    }

    public String getVerificationCode() {
        return verificationCode;
    }

    public void setVerificationCode(String verificationCode) {
        this.verificationCode = verificationCode;
    }

    public Date getStartTime() {
        return startTime;
    }

    public void setStartTime(Date startTime) {
        this.startTime = startTime;
    }

    public AuthenticationStatus getStatus() {
        return status;
    }

    public void setStatus(AuthenticationStatus status) {
        this.status = status;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public SmartIdAuthenticationSession() {
    }

    public SmartIdAuthenticationSession(String userIdCode, CountryCode countryCode) {
        setUserIdCode(userIdCode);
        setCountryCode(countryCode);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("MobileIdAuthenticationSessionData{");
        sb.append("userIdCode='").append(userIdCode).append('\'');
        sb.append(", givenName='").append(givenName).append('\'');
        sb.append(", surName='").append(surName).append('\'');
        sb.append(", countryCode=").append(countryCode);
        sb.append(", authenticationHash=");
        if (authenticationHash != null) {
            sb.append("(type=").append(authenticationHash.getHashType())
                    .append(", hash='").append(authenticationHash.getHashInBase64()).append("\')");
        } else {
            sb.append("null");
        }
        sb.append(", verificationCode='").append(verificationCode).append('\'');
        sb.append(", startTime='").append(startTime).append('\'');
        sb.append(", status=").append(status);
        sb.append(", certificate='").append(certificate != null ? shortenLongString(certificate.toString()) : null).append('\'');
        sb.append(", errorCode='").append(errorCode).append('\'');
        sb.append('}');
        return sb.toString();
    }

    private String shortenLongString(String str) {
        if (str.length() <= 21) {
            return str;
        }

        return str.substring(1, 10) + "..." + str.substring(str.length() - 10);
    }

    public enum CountryCode {
        EE,
        LT,
        LV
    }

    public enum AuthenticationStatus {

        PENDING,
        ERROR,
        USER_NOT_FOUND,
        USER_AUTHENTICATED
    }
}
