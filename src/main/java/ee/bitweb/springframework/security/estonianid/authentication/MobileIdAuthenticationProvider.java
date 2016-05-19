package ee.bitweb.springframework.security.estonianid.authentication;

import ee.bitweb.springframework.security.estonianid.MobileIdAuthenticationException;
import ee.bitweb.springframework.security.estonianid.MobileIdAuthenticationOutstandingException;
import ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetails;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Created by taavisikk on 5/12/16.
 */
public class MobileIdAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    private MobileIdAuthenticationService authenticationService;
    private UserDetailsService userDetailsService;

    public void afterPropertiesSet() {
        Assert.notNull(authenticationService, "authenticationService must be set");
        Assert.notNull(userDetailsService, "userDetailsService must be set");
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MobileIdAuthenticationToken token = (MobileIdAuthenticationToken) authentication;

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

        EstonianIdUserDetails userDetails = retrieveUser(token);

        if (!ObjectUtils.isEmpty(userDetails)) {
            token = new MobileIdAuthenticationToken(userDetails.getAuthorities(), token.getUserPhoneNo(),
                    token.getUserLanguageCode(), token.getAuthSession());
            token.setUserIdCode(token.getAuthSession().getUserIdCode());
            token.setAuthenticated(true);
            token.setDetails(null);
            token.setPrincipal(userDetails);
        }

        return token;
    }

    /**
     * Allows implementation specific ways to retrieve (or if needed, create/update) the user.
     *
     * @param token The authentication request
     * @return user information (never null, exception should be thrown)
     */
    protected EstonianIdUserDetails retrieveUser(MobileIdAuthenticationToken token) throws AuthenticationException {

        return (EstonianIdUserDetails) userDetailsService.loadUserByUsername(token.getUserIdCode());
    }

    public boolean supports(Class<?> authentication) {

        return MobileIdAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setAuthenticationService(MobileIdAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
