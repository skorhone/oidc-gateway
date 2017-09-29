package fi.kela.auth.identitygateway.oicclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.stereotype.Controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import fi.kela.auth.identitygateway.config.AppConstants;
import fi.kela.auth.identitygateway.config.IGWConfiguration;
import fi.kela.auth.identitygateway.util.URLs;

/**
 * OpenID Connect service
 *
 */
@Controller
public class OICService {
	private static final Logger logger = Logger.getLogger(OICService.class);
	@Autowired
	private IGWConfiguration appPropValues;

	public String getLoginProviderURL(String state, String redirectURI) throws IOException {
		return URLs.concatURL(appPropValues.getLoginProvider(), "",
				"response_type=code&scope=openid&client_id="
						+ URLEncoder.encode(appPropValues.getClientId(), AppConstants.ENCODING) + "&state="
						+ URLEncoder.encode(state, AppConstants.ENCODING) + "&redirect_uri="
						+ URLEncoder.encode(redirectURI, AppConstants.ENCODING));
	}

	public Token getToken(String code, String redirectURI) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(appPropValues.getTokenProvider()).openConnection();
		sendTokenRequest(connection, code, redirectURI);
		Token token = readTokenResponse(connection);
		if (!isValidToken(token)) {
			throw new IllegalStateException("Token is not valid");
		}
		return token;
	}

	private void sendTokenRequest(HttpURLConnection connection, String code, String redirectURI) throws IOException {
		connection.setDoOutput(true);
		connection.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		connection.setRequestMethod("POST");
		connection.getOutputStream()
				.write(("grant_type=authorization_code" + "&code=" + URLEncoder.encode(code, AppConstants.ENCODING)
						+ "&redirect_uri=" + URLEncoder.encode(redirectURI, AppConstants.ENCODING))
								.getBytes(AppConstants.ENCODING));
	}

	private boolean isTokenInResponse(HttpURLConnection connection) throws IOException {
		String contentType = connection.getContentType();
		return connection.getResponseCode() == 200 && contentType != null && contentType.startsWith("application/json");
	}

	private Token readTokenResponse(HttpURLConnection connection) throws IOException {
		if (!isTokenInResponse(connection)) {
			// TODO: Fix this
			throw new IllegalStateException("No token?!");
		}
		return readResponse(connection);
	}

	private Token readResponse(HttpURLConnection connection) throws IOException, UnsupportedEncodingException {
		try (InputStream is = connection.getInputStream();
				InputStreamReader isr = new InputStreamReader(is, AppConstants.ENCODING)) {
			char[] buf = new char[4096];
			int cnt;
			StringBuilder response = new StringBuilder();
			while ((cnt = isr.read(buf)) > 0) {
				response.append(buf, 0, cnt);
			}
			BasicJsonParser parser = new BasicJsonParser();
			Map<String, Object> token = parser.parseMap(response.toString());

			String idToken = token.get("id_token").toString();
			String accessToken = token.get("access_token").toString();
			String tokenType = token.get("token_type").toString();
			int expiresIn = ((Number) token.get("expires_in")).intValue();
			return new Token(idToken, accessToken, tokenType, expiresIn);
		}
	}

	private boolean isValidToken(Token token) {
		boolean valid = false;
		try {
			Algorithm algorithm = Algorithm.HMAC256("secret");
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(appPropValues.getIssuer()).build();
			DecodedJWT jwt = verifier.verify(token.getId_token());
			valid = true;
		} catch (UnsupportedEncodingException exception) {
			// UTF-8 encoding not supported
			logger.warn("Invalid token: " + token, exception);
		} catch (JWTVerificationException exception) {
			// Invalid signature/claims
			logger.warn("Invalid token: " + token, exception);
		}
		return valid;
	}
}