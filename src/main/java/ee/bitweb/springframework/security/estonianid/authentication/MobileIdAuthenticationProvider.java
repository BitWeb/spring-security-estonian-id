package ee.bitweb.springframework.security.estonianid.authentication;

import ee.bitweb.springframework.security.estonianid.MobileIdAuthenticationException;
import ee.bitweb.springframework.security.estonianid.MobileIdAuthenticationOutstandingException;
import ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetails;
import ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetailsService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Created by taavisikk on 5/12/16.
 */
public class MobileIdAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    private MobileIdAuthenticationService authenticationService;
    private EstonianIdUserDetailsService userDetailsService;
    private boolean createNewUsers = false;

    public void afterPropertiesSet() {
        Assert.notNull(authenticationService, "authenticationService must be set");
        Assert.notNull(userDetailsService, "userDetailsService must be set");
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ee.bitweb.springframework.security.estonianid.authentication.MobileIdAuthenticationToken token = (ee.bitweb.springframework.security.estonianid.authentication.MobileIdAuthenticationToken) authentication;

        if (ObjectUtils.isEmpty(token.getAuthSession())) {
            token.setAuthSession(authenticationService.beginAuthentication(token.getUserPhoneNo(), token.getUserLanguageCode()));

            if (!token.getAuthSession().isAuthenticated()) {
                if (token.getAuthSession().isValidForPolling()) {
                    throw new MobileIdAuthenticationOutstandingException("Mobile ID authentication incomplete", token);
                } else {
                    throw new MobileIdAuthenticationException("Mobile ID authentication failed", token);
                }
            }
        } else {
            if (!token.getAuthSession().isAuthenticated()) {
                if (token.getAuthSession().isValidForPolling()) {
                    authenticationService.poll(token.getAuthSession());
                    if (!token.getAuthSession().isAuthenticated()) {
                        if (token.getAuthSession().isValidForPolling()) {
                            throw new MobileIdAuthenticationOutstandingException("Mobile ID authentication incomplete", token);
                        } else {
                            throw new MobileIdAuthenticationException("Mobile ID authentication failed", token);
                        }
                    }
                } else {
                    throw new MobileIdAuthenticationException("Mobile ID authentication failed", token);
                }
            }
        }

        token.setUserIdCode(token.getAuthSession().getUserIdCode());
        token.setUserGivenName(token.getAuthSession().getUserGivenName());
        token.setUserSurname(token.getAuthSession().getUserSurname());
        token.setAuthenticated(true);

        EstonianIdUserDetails userDetails = (EstonianIdUserDetails) userDetailsService.loadUserDetails(token);
        boolean justCreated = false;

        if (ObjectUtils.isEmpty(userDetails)) {
            if (createNewUsers) {
                userDetails = userDetailsService.saveUserDetails(token);
                justCreated = true;
            }
        }
        if (!ObjectUtils.isEmpty(userDetails)) {
            if (!justCreated) {
                userDetailsService.updateUserDetails(userDetails, token);
            }
            token = new ee.bitweb.springframework.security.estonianid.authentication.MobileIdAuthenticationToken(userDetails.getAuthorities(),
                    token.getUserPhoneNo(), token.getUserLanguageCode(), token.getAuthSession());
            token.setUserIdCode(token.getAuthSession().getUserIdCode());
            token.setAuthenticated(true);
            token.setDetails(null);
            token.setPrincipal(userDetails);
        }

        return token;
    }

    public boolean supports(Class<?> authentication) {

        return MobileIdAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setAuthenticationService(MobileIdAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public void setUserDetailsService(EstonianIdUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setCreateNewUsers(boolean createNewUsers) {
        this.createNewUsers = createNewUsers;
    }
}
