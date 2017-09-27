package fi.kela.auth.openid.test;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

public class TokenServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final String ENCODING = "utf-8";

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		try {
			Instant now = Instant.now();
			Algorithm algorithm = Algorithm.HMAC256("secret");
			String token = JWT.create().withIssuer("https://openid.kela.fi").withSubject("010101-000A")
					.withClaim("name", "Matti Muinoinen").withArrayClaim("groupIds", new String[] { "verkkoasiakas" })
					.withIssuedAt(Date.from(now)).withExpiresAt(Date.from(now.plus(Duration.ofHours(2))))
					.withAudience("https://kela.fi").sign(algorithm);
			resp.setContentType("application/json");
			resp.getOutputStream().write(token.getBytes(ENCODING));
		} catch (UnsupportedEncodingException exception) {
			// UTF-8 encoding not supported
		} catch (JWTCreationException exception) {
			// Invalid Signing configuration / Couldn't convert Claims.
		}
	}
}