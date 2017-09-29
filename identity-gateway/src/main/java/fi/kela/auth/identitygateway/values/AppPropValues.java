package fi.kela.auth.identitygateway.values;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public class AppPropValues {
	private static final String PROXY_TARGET = "igw.proxy_target";
	private static final String COOKIE_PATH = "igw.cookie_path";
	private static final String CALLBACK_SERVICE_CONTEXT = "igw.callback_service_context";
	private static final String LOGOUT_SERVICE_CONTEXT = "igw.logout_service_context";
	private static final String ERROR_CONTEXT = "igw.error_context";
	private static final String AUTH_SERVICE_CONTEXT = "igw.auth_service_context";
	private static final String ERROR_REDIRECT_TARGET = "igw.error_redirect_target";
	private static final String LOGOUT_REDIRECT_TARGET = "igw.logout_redirect_target";
	private static final String AUTH_TOKEN_COOKIE = "igw.auth_token_cookie";
	private static final String STATE_COOKIE = "igw.state_cookie";
	private static final String STATE_COOKIE_EXP = "igw.state_cookie_expire";
	private static final String ISSUER = "igw.issuer";
	private static final String ENCODING = "igw.encoding";
	private static final String LOGIN_PROVIDER = "igw.login_provider";
	private static final String TOKEN_PROVIDER = "igw.token_provider";
	private static final String CLIENT_ID = "igw.client_id";
	@Autowired
	private Environment env;

	public String getProxyTarget() {
		return env.getProperty(PROXY_TARGET);
	}

	public String getCookiePath() {
		return env.getProperty(COOKIE_PATH);
	}

	public String getCallbackServiceContext() {
		return env.getProperty(CALLBACK_SERVICE_CONTEXT);
	}

	public String getLogoutServiceContext() {
		return env.getProperty(LOGOUT_SERVICE_CONTEXT);
	}

	public String getErrorContext() {
		return env.getProperty(ERROR_CONTEXT);
	}

	public String getAuthServiceContext() {
		return env.getProperty(AUTH_SERVICE_CONTEXT);
	}

	public String getErrorRedirectTarget() {
		return env.getProperty(ERROR_REDIRECT_TARGET);
	}

	public String getLogoutRedirectTarget() {
		return env.getProperty(LOGOUT_REDIRECT_TARGET);
	}

	public String getAuthTokenCookie() {
		return env.getProperty(AUTH_TOKEN_COOKIE);
	}

	public String getStateCookie() {
		return env.getProperty(STATE_COOKIE);
	}
	
	public int getStateCookieExpire() {
		return Integer.parseInt(env.getProperty(STATE_COOKIE_EXP));
	}

	public String getIssuer() {
		return env.getProperty(ISSUER);
	}

	public String getEncoding() {
		return env.getProperty(ENCODING);
	}

	public String getLoginProvider() {
		return env.getProperty(LOGIN_PROVIDER);
	}

	public String getTokenProvider() {
		return env.getProperty(TOKEN_PROVIDER);
	}

	public String getClientId() {
		return env.getProperty(CLIENT_ID);
	}
}