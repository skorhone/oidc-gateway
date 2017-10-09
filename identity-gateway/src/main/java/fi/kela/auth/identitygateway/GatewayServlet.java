package fi.kela.auth.identitygateway;

import java.util.concurrent.ExecutorService;
import java.util.function.Consumer;

import javax.servlet.AsyncContext;
import javax.servlet.GenericServlet;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import fi.kela.auth.identitygateway.auth.AuthService;
import fi.kela.auth.identitygateway.oidcclient.Token;
import fi.kela.auth.identitygateway.proxy.ProxyService;
import fi.kela.auth.identitygateway.util.ProxyContext;

public class GatewayServlet extends GenericServlet {
	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(GatewayServlet.class);
	private IGWConfiguration igwConfiguration;
	private AuthService authService;
	private ProxyService proxyService;
	private ExecutorService executorService;

	public GatewayServlet(IGWConfiguration igwConfiguration, AuthService authService, ProxyService proxyService,
			ExecutorService executorService) {
		this.igwConfiguration = igwConfiguration;
		this.authService = authService;
		this.proxyService = proxyService;
		this.executorService = executorService;
	}

	@Override
	public void service(ServletRequest req, ServletResponse res) {
		AsyncContext asyncContext = req.startAsync();
		ProxyContext proxyContext = new ProxyContext(asyncContext, ((HttpServletRequest) req).getServletPath(),
				((HttpServletRequest) req).getQueryString());
		Runnable onComplete = () -> {
			try {
				asyncContext.complete();
			} catch (Exception exception) {
				logger.warn("Could not complete request", exception);
			}
		};
		Consumer<Exception> onError = (exception) -> {
			logger.warn(exception.getMessage(), exception);
			handleError(proxyContext, onComplete);
		};
		Runnable requestHandler = () -> {
			service(proxyContext, onComplete, onError);
		};
		executorService.submit(requestHandler);
	}

	private void service(ProxyContext proxyContext, Runnable onComplete, Consumer<Exception> onError) {
		if (isError(proxyContext)) {
			handleError(proxyContext, onComplete);
		} else if (authService.isLogout(proxyContext)) {
			authService.logout(proxyContext, onComplete);
		} else if (authService.isAuthenticationCallback(proxyContext)) {
			authService.authenticate(proxyContext, onComplete, onError);
		} else {
			Consumer<Token> onTokenComplete = (token) -> {
				try {
					if (token == null && !isAllowAnonymous(proxyContext)) {
						authService.redirectToAuthentication(proxyContext);
					} else {
						proxyService.proxy(proxyContext, token.getAccessToken());
					}
					onComplete.run();
				} catch (Exception proxyException) {
					onError.accept(proxyException);
				}
			};
			authService.retrieveAuthenticationToken(proxyContext, onTokenComplete, onError);
		}
	}

	private boolean isError(ProxyContext proxyContext) {
		return igwConfiguration.getErrorContext().equals(proxyContext.getServletPath());
	}

	private boolean isAllowAnonymous(ProxyContext proxyContext) {
		return igwConfiguration.getExcludedContexts().stream()
				.anyMatch(c -> proxyContext.getServletPath().startsWith(c));
	}

	private void handleError(ProxyContext proxyContext, Runnable onComplete) {
		try {
			logger.info("Redirecting to error page");
			proxyContext.getResponse().sendRedirect(igwConfiguration.getErrorRedirectTarget());
		} catch (Exception exception) {
			logger.warn("Could not redirect user to error target");
		} finally {
			onComplete.run();
		}
	}
}
