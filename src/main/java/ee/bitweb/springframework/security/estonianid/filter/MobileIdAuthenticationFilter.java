package ee.bitweb.springframework.security.estonianid.filter;

import ee.bitweb.springframework.security.estonianid.MobileIdAuthenticationException;
import ee.bitweb.springframework.security.estonianid.MobileIdAuthenticationOutstandingException;
import ee.bitweb.springframework.security.estonianid.authentication.MobileIdAuthenticationHandler;
import ee.bitweb.springframework.security.estonianid.authentication.MobileIdAuthenticationToken;
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
 * Created by taavisikk on 5/10/16.
 */
public class MobileIdAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

    private String filterProcessesUrl = "/j_spring_mid_security_check";
    private AuthenticationManager authenticationManager;
    private ApplicationEventPublisher applicationEventPublisher;
    private AuthenticationSuccessHandler authenticationSuccessHandler = new MobileIdAuthenticationHandler();
    private AuthenticationFailureHandler authenticationFailureHandler = new MobileIdAuthenticationHandler();

    private LocaleResolver localeResolver = new CookieLocaleResolver();
    private String defaultLanguageCode = "EST";
    private Map<String, String> localeToLangMap;

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(authenticationManager, "authenticationManager must be specified");
        Assert.notNull(applicationEventPublisher, "applicationEventPublisher must be specified");
        if (ObjectUtils.isEmpty(localeToLangMap)) {
            localeToLangMap = new HashMap<String, String>();
            localeToLangMap.put("et_EE", "EST");
            localeToLangMap.put("en_EE", "ENG");
            localeToLangMap.put("ru_EE", "RUS");
            localeToLangMap.put("lt_EE", "LIT");
        }
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;

        if(!request.getRequestURI().contains(filterProcessesUrl)) {
            chain.doFilter(request, response);
            return;
        }

        logger.debug("Request requires MobileId authentication");

        Authentication token = SecurityContextHolder.getContext().getAuthentication();

        try {
            token = attemptAuthentication(request, (MobileIdAuthenticationToken) token);

            if(ObjectUtils.isEmpty(token)) {
                return;
            }

            successfulAuthentication(request, response, token);
        } catch(MobileIdAuthenticationOutstandingException e) {
            insufficientAuthentication(request, response, e);
        } catch(AuthenticationException e) {
            unsuccessfulAuthentication(request, response, e);
        }
    }

    private Authentication attemptAuthentication(HttpServletRequest request, MobileIdAuthenticationToken token) throws AuthenticationException {
        logger.debug("Attempting MobileId authentication");

        String phoneNo = obtainPhoneNo(request);
        if (phoneNo != null) {
            phoneNo = phoneNo.trim();
        }

        if(token == null) {
            token = new MobileIdAuthenticationToken(phoneNo);
        } else {
            if(!token.getUserPhoneNo().equals(phoneNo)) {
                token = new MobileIdAuthenticationToken(phoneNo);
            }
        }

        Locale locale = localeResolver.resolveLocale(request);
        String languageCode = defaultLanguageCode;
        if (!ObjectUtils.isEmpty(locale) && localeToLangMap.containsKey(locale.toString())) {
            languageCode = localeToLangMap.get(locale.toString());
        }
        token.setUserLanguageCode(languageCode);

        return authenticationManager.authenticate(token);
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                          Authentication authentication) throws IOException, ServletException {

        SecurityContextHolder.getContext().setAuthentication(authentication);
        applicationEventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authentication, getClass()));
        authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
    }

    private void insufficientAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            MobileIdAuthenticationException e) throws IOException, ServletException {

        SecurityContextHolder.getContext().setAuthentication(e.getToken());
        authenticationFailureHandler.onAuthenticationFailure(request, response, e);
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException e) throws IOException, ServletException {

        SecurityContextHolder.clearContext();
        authenticationFailureHandler.onAuthenticationFailure(request, response, e);
    }

    private String obtainPhoneNo(HttpServletRequest request) {
        try {
            return URLDecoder.decode(request.getParameter("phoneNo"), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            logger.error(e);
            return null;
        }
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

    public String getDefaultLanguageCode() {
        return defaultLanguageCode;
    }

    public void setDefaultLanguageCode(String defaultLanguageCode) {
        this.defaultLanguageCode = defaultLanguageCode;
    }

    public Map<String, String> getLocaleToLangMap() {
        return localeToLangMap;
    }

    public void setLocaleToLangMap(Map<String, String> localeToLangMap) {
        this.localeToLangMap = localeToLangMap;
    }
}
