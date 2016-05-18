package ee.bitweb.springframework.security.estonianid.authentication;

import java.util.Date;

/**
 * Created by taavisikk on 5/10/16.
 */
public class MobileIdAuthenticationSession {

    private String sessionCode;
    private String challengeId;

    private String userIdCode;
    private String userGivenName;
    private String userSurname;

    private Date timeStarted;
    private Date timePolled;

    private String status = "";
    private Integer errorCode = 0;

    public boolean isValidForPolling() {

        return errorCode == 0 && (status.equals(MobileIdAuthenticationService.ST_OK)
                || status.equals(MobileIdAuthenticationService.ST_OUTSTANDING_TRANSACTION));
    }

    public boolean isAuthenticated() {

        return status.equals(MobileIdAuthenticationService.ST_USER_AUTHENTICATED);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("sessionCode: ");
        builder.append(sessionCode);
        builder.append("; challengeId: ");
        builder.append(challengeId);
        builder.append("; userIdCode: ");
        builder.append(userIdCode);
        builder.append("; userGivenName: ");
        builder.append(userGivenName);
        builder.append("; userSurname: ");
        builder.append(userSurname);
        builder.append("; timeStarted: ");
        builder.append(timeStarted);
        builder.append("; timePolled: ");
        builder.append(timePolled);
        builder.append("; status: ");
        builder.append(status);
        builder.append("; errorCode: ");
        builder.append(errorCode);

        return builder.toString();
    }

    public String getSessionCode() {
        return sessionCode;
    }

    public void setSessionCode(String sessionCode) {
        this.sessionCode = sessionCode;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }

    public String getUserIdCode() {
        return userIdCode;
    }

    public void setUserIdCode(String userIdCode) {
        this.userIdCode = userIdCode;
    }

    public String getUserGivenName() {
        return userGivenName;
    }

    public void setUserGivenName(String userGivenName) {
        this.userGivenName = userGivenName;
    }

    public String getUserSurname() {
        return userSurname;
    }

    public void setUserSurname(String userSurname) {
        this.userSurname = userSurname;
    }

    public Date getTimeStarted() {
        return timeStarted;
    }

    public void setTimeStarted(Date timeStarted) {
        this.timeStarted = timeStarted;
    }

    public Date getTimePolled() {
        return timePolled;
    }

    public void setTimePolled(Date timePolled) {
        this.timePolled = timePolled;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Integer getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(Integer errorCode) {
        this.errorCode = errorCode;
    }
}
