package fi.kela.auth.identitygateway.oidcclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.auth0.jwt.interfaces.Verification;

import fi.kela.auth.identitygateway.oidcclient.key.KeyProvider;
import fi.kela.auth.identitygateway.util.AppConstants;
import fi.kela.auth.identitygateway.util.URLs;

/**
 * OpenID Connect service
 *
 */
@Service
public class OIDCService {
	private static final Logger logger = Logger.getLogger(OIDCService.class);
	private OIDCConfiguration oidcConfiguration;
	private KeyProvider keyProvider;

	public OIDCService(OIDCConfiguration oidcConfiguration, KeyProvider keyProvider) {
		this.oidcConfiguration = oidcConfiguration;
		this.keyProvider = keyProvider;
	}

	public String getLoginProviderURL(String state, String redirectURI) {
		try {
			return URLs.concatURL(oidcConfiguration.getLoginProvider(), "",
					"response_type=code&scope=openid,offline_access&client_id="
							+ URLEncoder.encode(oidcConfiguration.getClientId(), AppConstants.ENCODING) + "&state="
							+ URLEncoder.encode(state, AppConstants.ENCODING) + "&redirect_uri="
							+ URLEncoder.encode(redirectURI, AppConstants.ENCODING));
		} catch (UnsupportedEncodingException exception) {
			throw new IllegalStateException("Could not get login provider URL", exception);
		}
	}

	public Token getTokenWithRefreshToken(String refreshToken)
			throws TokenProviderException, TokenNotFoundException, TokenNotValidException {
		HttpURLConnection connection = getTokenEndpointConnection();
		TokenRequest tokenRequest = TokenRequest.createWithRefreshToken(oidcConfiguration.getClientId(),
				oidcConfiguration.getClientSecret(), refreshToken);
		sendTokenRequest(connection, tokenRequest);
		return readTokenResponse(connection);
	}

	public Token getTokenWithAuthorizationCode(String code, String redirectURI)
			throws TokenProviderException, TokenNotFoundException, TokenNotValidException {
		HttpURLConnection connection = getTokenEndpointConnection();
		TokenRequest tokenRequest = TokenRequest.createWithCode(oidcConfiguration.getClientId(),
				oidcConfiguration.getClientSecret(), redirectURI, code);
		sendTokenRequest(connection, tokenRequest);
		return readTokenResponse(connection);
	}

	private HttpURLConnection getTokenEndpointConnection() throws TokenProviderException {
		try {
			return (HttpURLConnection) new URL(oidcConfiguration.getTokenProvider()).openConnection();
		} catch (Exception exception) {
			throw new TokenProviderException(exception);
		}
	}

	private void logTokenError(HttpURLConnection connection) {
		try {
			try (InputStream is = connection.getResponseCode() > 200 ? connection.getErrorStream()
					: connection.getInputStream()) {
				String response = readResponse(is);
				logger.error("Received error while obtaining token. Connection rc: " + connection.getResponseCode()
						+ " Response: " + response);
			}
		} catch (Exception exception) {
			logger.error("Unable to retrieve error message", exception);
		}
	}

	private void sendTokenRequest(HttpURLConnection connection, TokenRequest tokenRequest)
			throws TokenProviderException {
		try {
			connection.setDoOutput(true);
			connection.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestMethod("POST");
			String form = tokenRequest.toFormEncoded();
			logger.debug("Token request: " + form);
			connection.getOutputStream().write(form.getBytes(AppConstants.ENCODING));
		} catch (Exception exception) {
			throw new TokenProviderException(exception);
		}
	}

	private boolean isTokenInResponse(HttpURLConnection connection) throws TokenProviderException {
		try {
			String contentType = connection.getContentType();
			return connection.getResponseCode() == 200 && contentType != null
					&& contentType.startsWith("application/json");
		} catch (Exception exception) {
			throw new TokenProviderException(exception);
		}
	}

	private Token readTokenResponse(HttpURLConnection connection)
			throws TokenProviderException, TokenNotFoundException, TokenNotValidException {
		if (!isTokenInResponse(connection)) {
			logTokenError(connection);
			throw new TokenNotFoundException();
		}
		Token token = readResponse(connection);
		validateToken(token);
		return token;
	}

	private Token readResponse(HttpURLConnection connection) throws TokenProviderException {
		String response;
		try (InputStream is = connection.getInputStream()) {
			response = readResponse(is);
		} catch (IOException exception) {
			throw new TokenProviderException(exception);
		}
		BasicJsonParser parser = new BasicJsonParser();
		Map<String, Object> token = parser.parseMap(response);

		String accessToken = token.get("access_token").toString();
		String refreshToken = token.get("refresh_token").toString();
		int expiresIn = ((Number) token.get("expires_in")).intValue();
		return new Token(accessToken, refreshToken, System.currentTimeMillis() + (expiresIn * 1000));
	}

	private String readResponse(InputStream is) throws IOException, UnsupportedEncodingException {
		String response;
		try (InputStreamReader isr = new InputStreamReader(is, AppConstants.ENCODING)) {
			StringBuilder responseBuilder = new StringBuilder();
			char[] buf = new char[4096];
			int cnt;
			while ((cnt = isr.read(buf)) > 0) {
				responseBuilder.append(buf, 0, cnt);
			}
			response = responseBuilder.toString();
		}
		return response;
	}

	private void validateToken(Token token) throws TokenNotValidException {
		try {
			Algorithm algorithm;
			if ("RS256".equalsIgnoreCase(oidcConfiguration.getSignatureAlgorithm())) {
				algorithm = Algorithm.RSA256(new RSAKeyProvider() {
					@Override
					public RSAPublicKey getPublicKeyById(String keyId) {
						return keyProvider.getRSAPublicKey(keyId);
					}

					@Override
					public String getPrivateKeyId() {
						throw new UnsupportedOperationException();
					}

					@Override
					public RSAPrivateKey getPrivateKey() {
						throw new UnsupportedOperationException();
					}
				});
			} else {
				algorithm = Algorithm.HMAC256(oidcConfiguration.getSecretKey());
			}
			Verification verification = JWT.require(algorithm);
			if (oidcConfiguration.getIssuer() != null) {
				verification = verification.withIssuer(oidcConfiguration.getIssuer());
			}
			JWTVerifier verifier = verification.build();
			DecodedJWT jwt = verifier.verify(token.getAccessToken());
		} catch (Exception exception) {
			throw new TokenNotValidException(exception);
		}
	}
}