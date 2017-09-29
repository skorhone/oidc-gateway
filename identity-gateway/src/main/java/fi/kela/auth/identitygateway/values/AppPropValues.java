package fi.kela.auth.identitygateway.values;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public class AppPropValues {

	@Autowired
	Environment env;
	
	private final String PROXY_TARGET="proxy_target";
	private final String COOKIE_PATH = "cookie_path";
	private final String CALLBACK_SERVICE_CONTEXT = "callback_service_context";
	private final String LOGOUT_SERVICE_CONTEXT = "logout_service_context";
	private final String ERROR_CONTEXT = "error_context";
	private final String AUTH_SERVICE_CONTEXT = "auth_service_context";
	private final String ERROR_REDIRECT_TARGET = "error_redirect_target";
	private final String LOGOUT_REDIRECT_TARGET = "logout_redirect_target";
	private final String AUTH_TOKEN_COOKIE = "auth_token_cookie";
	private final String STATE_COOKIE = "state_cookie";
	private final String ISSUER = "issuer";
	private final String ENCODING = "encoding";
	private final String LOGIN_PROVIDER = "login_provider";
	private final String TOKEN_PROVIDER = "token_provider";
	private final String CLIENT_ID = "client_id";
	
	

	public AppPropValues() {
		super();
	}


	public String getPROXY_TARGET() {
		return env.getProperty(PROXY_TARGET);
	}


	public String getCOOKIE_PATH() {
		return env.getProperty(COOKIE_PATH);
	}


	public String getCALLBACK_SERVICE_CONTEXT() {
		return env.getProperty(CALLBACK_SERVICE_CONTEXT);
	}


	public String getLOGOUT_SERVICE_CONTEXT() {
		return env.getProperty(LOGOUT_SERVICE_CONTEXT);
	}


	public String getERROR_CONTEXT() {
		return env.getProperty(ERROR_CONTEXT);
	}


	public String getAUTH_SERVICE_CONTEXT() {
		return env.getProperty(AUTH_SERVICE_CONTEXT);
	}


	public String getERROR_REDIRECT_TARGET() {
		return env.getProperty(ERROR_REDIRECT_TARGET);
	}


	public String getLOGOUT_REDIRECT_TARGET() {
		return env.getProperty(LOGOUT_REDIRECT_TARGET);
	}


	public String getAUTH_TOKEN_COOKIE() {
		return env.getProperty(AUTH_TOKEN_COOKIE);
	}


	public String getSTATE_COOKIE() {
		return env.getProperty(STATE_COOKIE);
	}


	public String getISSUER() {
		return env.getProperty(ISSUER);
	}


	public String getENCODING() {
		return env.getProperty(ENCODING);
	}


	public String getLOGIN_PROVIDER() {
		return env.getProperty(LOGIN_PROVIDER);
	}


	public String getTOKEN_PROVIDER() {
		return env.getProperty(TOKEN_PROVIDER);
	}


	public String getCLIENT_ID() {
		return env.getProperty(CLIENT_ID);
	}
	
	

}