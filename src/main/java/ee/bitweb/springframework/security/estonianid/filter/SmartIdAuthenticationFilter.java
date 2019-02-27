package ee.bitweb.springframework.security.estonianid.filter;

import ee.bitweb.springframework.security.estonianid.*;
import ee.bitweb.springframework.security.estonianid.authentication.SmartIdAuthenticationHandler;
import ee.bitweb.springframework.security.estonianid.authentication.SmartIdAuthenticationSession;
import ee.bitweb.springframework.security.estonianid.authentication.SmartIdAuthenticationToken;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;


/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

    private String filterProcessesUrl = "/j_spring_sid_security_check";
    private AuthenticationManager authenticationManager;
    private ApplicationEventPublisher applicationEventPublisher;
    private AuthenticationSuccessHandler authenticationSuccessHandler = new SmartIdAuthenticationHandler();
    private AuthenticationFailureHandler authenticationFailureHandler = new SmartIdAuthenticationHandler();

    private LocaleResolver localeResolver = new CookieLocaleResolver();
    private SmartIdAuthenticationSession.CountryCode defaultCountryCode = SmartIdAuthenticationSession.CountryCode.EE;
    private Map<String, SmartIdAuthenticationSession.CountryCode> localeToCountryMap;

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(authenticationManager, "authenticationManager must be specified");
        Assert.notNull(applicationEventPublisher, "applicationEventPublisher must be specified");

        if (ObjectUtils.isEmpty(localeToCountryMap)) {
            localeToCountryMap = new HashMap<String, SmartIdAuthenticationSession.CountryCode>();
            localeToCountryMap.put("et_EE", SmartIdAuthenticationSession.CountryCode.EE);
            localeToCountryMap.put("lt_LT", SmartIdAuthenticationSession.CountryCode.LT);
            localeToCountryMap.put("lv_LV", SmartIdAuthenticationSession.CountryCode.LV);
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;

        if (!request.getRequestURI().contains(filterProcessesUrl)) {
            chain.doFilter(request, response);
            return;
        }

        logger.debug("Request requires Smart-ID authentication");

        Authentication token = SecurityContextHolder.getContext().getAuthentication();

        try {
            token = attemptAuthentication(request, (SmartIdAuthenticationToken) token);

            if (ObjectUtils.isEmpty(token)) {
                return;
            }

            successfulAuthentication(request, response, token);
        } catch (SmartIdAuthenticationPendingException e) {
            insufficientAuthentication(request, response, e);
        } catch (AuthenticationException e) {
            unsuccessfulAuthentication(request, response, e);
        }
    }

    private Authentication attemptAuthentication(HttpServletRequest request, SmartIdAuthenticationToken token)
            throws AuthenticationException {
        logger.debug("Attempting Smart-ID authentication");

        String userIdCode = obtainUserIdCode(request);
        if (userIdCode != null) {
            userIdCode = userIdCode.trim();
        }

        SmartIdAuthenticationSession.CountryCode countryCode = obtainCountryCode(request);
        if (countryCode == null) {
            countryCode = defaultCountryCode;

            Locale locale = localeResolver.resolveLocale(request);
            if (!ObjectUtils.isEmpty(locale) && localeToCountryMap.containsKey(locale.toString())) {
                countryCode = localeToCountryMap.get(locale.toString());
            }
        }

        if (token == null) {
            token = new SmartIdAuthenticationToken(userIdCode, countryCode);
        } else {
            if (!token.getUserIdCode().equals(userIdCode)) {
                token = new SmartIdAuthenticationToken(userIdCode, countryCode);
            }
        }

        return authenticationManager.authenticate(token);
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                          Authentication authentication) throws IOException, ServletException {

        SecurityContextHolder.getContext().setAuthentication(authentication);
        applicationEventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authentication, getClass()));
        authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
    }

    private void insufficientAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            SmartIdAuthenticationException e) throws IOException, ServletException {

        SecurityContextHolder.getContext().setAuthentication(e.getToken());
        authenticationFailureHandler.onAuthenticationFailure(request, response, e);
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException e) throws IOException, ServletException {

        SecurityContextHolder.clearContext();
        authenticationFailureHandler.onAuthenticationFailure(request, response, e);
    }

    private String obtainUserIdCode(HttpServletRequest request) {
        String userIdCode = request.getParameter("userIdCode");

        if (userIdCode != null) {
            try {
                return URLDecoder.decode(userIdCode, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                logger.error(e);
                return null;
            }
        }
        return null;
    }

    private SmartIdAuthenticationSession.CountryCode obtainCountryCode(HttpServletRequest request) {
        String countryCode = request.getParameter("countryCode");

        if (countryCode != null) {
            return SmartIdAuthenticationSession.CountryCode.valueOf(countryCode);
        }
        return null;
    }

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public ApplicationEventPublisher getApplicationEventPublisher() {
        return applicationEventPublisher;
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    public AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
        return authenticationSuccessHandler;
    }

    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    public AuthenticationFailureHandler getAuthenticationFailureHandler() {
        return authenticationFailureHandler;
    }

    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    public Object getLocaleResolver() {
        return localeResolver;
    }

    public void setLocaleResolver(LocaleResolver localeResolver) {
        this.localeResolver = localeResolver;
    }

    public SmartIdAuthenticationSession.CountryCode getDefaultCountryCode() {
        return defaultCountryCode;
    }

    public void setDefaultCountryCode(SmartIdAuthenticationSession.CountryCode defaultCountryCode) {
        this.defaultCountryCode = defaultCountryCode;
    }

    public Map<String, SmartIdAuthenticationSession.CountryCode> getLocaleToCountryMap() {
        return localeToCountryMap;
    }

    public void setLocaleToCountryMap(Map<String, SmartIdAuthenticationSession.CountryCode> localeToCountryMap) {
        this.localeToCountryMap = localeToCountryMap;
    }
}
