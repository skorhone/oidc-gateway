package fi.kela.auth.identitygateway.config;

import java.util.Collections;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("igw")
public class IGWConfiguration {
	private String location;
	private String proxyTarget;
	private String callbackServiceContext;
	private String logoutServiceContext;
	private String errorContext;
	private List<String> excludedContexts;
	private String errorRedirectTarget;
	private String logoutRedirectTarget;
	private String cookiePath;
	private String signOnCookie;
	private String stateCookie;
	private int stateCookieExpire;

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public String getProxyTarget() {
		return proxyTarget;
	}

	public void setProxyTarget(String proxyTarget) {
		this.proxyTarget = proxyTarget;
	}

	public String getCallbackServiceContext() {
		return callbackServiceContext;
	}

	public void setCallbackServiceContext(String callbackServiceContext) {
		this.callbackServiceContext = callbackServiceContext;
	}

	public String getLogoutServiceContext() {
		return logoutServiceContext;
	}

	public void setLogoutServiceContext(String logoutServiceContext) {
		this.logoutServiceContext = logoutServiceContext;
	}

	public String getErrorContext() {
		return errorContext;
	}

	public void setErrorContext(String errorContext) {
		this.errorContext = errorContext;
	}

	public List<String> getExcludedContexts() {
		if (excludedContexts == null) {
			return Collections.emptyList();
		}
		return excludedContexts;
	}

	public void setExcludedContexts(List<String> excludedContexts) {
		this.excludedContexts = excludedContexts;
	}

	public String getErrorRedirectTarget() {
		return errorRedirectTarget;
	}

	public void setErrorRedirectTarget(String errorRedirectTarget) {
		this.errorRedirectTarget = errorRedirectTarget;
	}

	public String getLogoutRedirectTarget() {
		return logoutRedirectTarget;
	}

	public void setLogoutRedirectTarget(String logoutRedirectTarget) {
		this.logoutRedirectTarget = logoutRedirectTarget;
	}

	public String getCookiePath() {
		return cookiePath;
	}

	public void setCookiePath(String cookiePath) {
		this.cookiePath = cookiePath;
	}

	public String getSignOnCookie() {
		return signOnCookie;
	}

	public void setSignOnCookie(String authTokenCookie) {
		this.signOnCookie = authTokenCookie;
	}

	public String getStateCookie() {
		return stateCookie;
	}

	public void setStateCookie(String stateCookie) {
		this.stateCookie = stateCookie;
	}

	public int getStateCookieExpire() {
		return stateCookieExpire;
	}

	public void setStateCookieExpire(int stateCookieExpire) {
		this.stateCookieExpire = stateCookieExpire;
	}
}