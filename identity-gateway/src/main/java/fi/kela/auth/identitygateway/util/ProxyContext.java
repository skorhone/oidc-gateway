package fi.kela.auth.identitygateway.util;

import javax.servlet.AsyncContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProxyContext {
	private HttpServletRequest request;
	private HttpServletResponse response;
	private String servletPath;
	private String queryString;

	public ProxyContext(AsyncContext asyncContext, String servletPath, String queryString) {
		this.request = (HttpServletRequest) asyncContext.getRequest();
		this.response = (HttpServletResponse) asyncContext.getResponse();
		this.servletPath = servletPath;
		this.queryString = queryString;
	}

	public HttpServletRequest getRequest() {
		return request;
	}

	public HttpServletResponse getResponse() {
		return response;
	}

	public String getServletPath() {
		return servletPath;
	}
	
	public String getQueryString() {
		return queryString;
	}
}
