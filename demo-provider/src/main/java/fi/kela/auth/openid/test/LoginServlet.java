package fi.kela.auth.openid.test;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
	private static final String ENCODING = "utf-8";
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		// TODO: This should do suomi.fi login redirection.. but now we just reply as it was already done :-)
		String response_type = req.getParameter("code");
		String scope = req.getParameter("scope");
		String clientId = req.getParameter("client_id");
		String state = req.getParameter("state");
		String redirectURI = req.getParameter("redirect_uri");
		String code = "foobar";
		
		res.sendRedirect(redirectURI + "?code=" + URLEncoder.encode(code, ENCODING) + "&state=" + URLEncoder.encode(state, ENCODING));
	}
}
