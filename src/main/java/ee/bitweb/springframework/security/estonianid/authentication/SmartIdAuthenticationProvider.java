package ee.bitweb.springframework.security.estonianid.authentication;

import ee.bitweb.springframework.security.estonianid.SmartIdAuthenticationException;
import ee.bitweb.springframework.security.estonianid.SmartIdAuthenticationPendingException;
import ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetails;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    private SmartIdAuthenticationService authenticationService;

    protected UserDetailsService userDetailsService;

    public void afterPropertiesSet() {
        Assert.notNull(authenticationService, "authenticationService must be set");
        Assert.notNull(userDetailsService, "userDetailsService must be set");
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SmartIdAuthenticationToken token = (SmartIdAuthenticationToken) authentication;

        if (ObjectUtils.isEmpty(token.getAuthSession())) {
            token.setAuthSession(authenticationService.beginAuthentication(token.getUserIdCode(), token.getCountryCode()));

            if (!token.getAuthSession().isAuthenticated()) {
                if (token.getAuthSession().isPending()) {
                    throw new SmartIdAuthenticationPendingException("Smart-ID authentication pending", token);
                } else {
                    throw new SmartIdAuthenticationException("Smart-ID authentication failed", token);
                }
            }
        } else {
            if (!token.getAuthSession().isAuthenticated()) {
                if (token.getAuthSession().isPending()) {
                    try {
                        authenticationService.validate(token.getAuthSession());
                    } catch (Exception e) {
                        throw new SmartIdAuthenticationException("Smart-ID authentication failed", token, e);
                    }

                    if (!token.getAuthSession().isAuthenticated()) {
                        if (token.getAuthSession().isPending()) {
                            throw new SmartIdAuthenticationPendingException("Smart-ID authentication pending", token);
                        } else {
                            throw new SmartIdAuthenticationException("Smart-ID authentication failed", token);
                        }
                    }
                } else {
                    throw new SmartIdAuthenticationException("Smart-ID authentication failed", token);
                }
            }
        }

        token.setUserIdCode(token.getAuthSession().getUserIdCode());
        token.setUserGivenName(token.getAuthSession().getGivenName());
        token.setUserSurname(token.getAuthSession().getSurName());
        token.setAuthenticated(true);

        EstonianIdUserDetails userDetails = retrieveUser(token);

        if (!ObjectUtils.isEmpty(userDetails)) {
            token = new SmartIdAuthenticationToken(userDetails.getAuthorities(), token.getUserIdCode(),
                    token.getCountryCode(), token.getAuthSession());
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
    protected EstonianIdUserDetails retrieveUser(SmartIdAuthenticationToken token) throws AuthenticationException {
        try {
            return (EstonianIdUserDetails) userDetailsService.loadUserByUsername(token.getUserIdCode());
        } catch (UsernameNotFoundException e) {
            throw new SmartIdAuthenticationException(e.getMessage(), token, e);
        }
    }

    public boolean supports(Class<?> authentication) {

        return SmartIdAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setAuthenticationService(SmartIdAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
