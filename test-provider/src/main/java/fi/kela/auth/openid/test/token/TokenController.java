package fi.kela.auth.openid.test.token;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.apache.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import fi.kela.auth.openid.test.config.ProviderConfiguration;
import fi.kela.auth.openid.test.identity.Identity;
import fi.kela.auth.openid.test.identity.IdentityService;
import fi.kela.auth.openid.test.key.KeyException;
import fi.kela.auth.openid.test.key.KeyService;

@RestController
public class TokenController {
	private static final Logger logger = Logger.getLogger(TokenController.class);
	private ProviderConfiguration providerConfiguration;
	private IdentityService identityService;
	private KeyService keyService;

	public TokenController(ProviderConfiguration providerConfiguration, IdentityService identityService,
			KeyService keyService) {
		this.providerConfiguration = providerConfiguration;
		this.identityService = identityService;
		this.keyService = keyService;
	}

	@RequestMapping(value = "/token", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public Token createToken(TokenRequest request) throws UnsupportedGrantTypeException, TokenNotFoundException {
		logger.info("Processing token request");
		if ("authorization_code".equals(request.getGrant_type())) {
			return createTokenWithAuthorizationCode(request);
		}
		if ("refresh_token".equals(request.getGrant_type())) {
			return createTokenWithRefreshToken(request);
		}
		throw new UnsupportedGrantTypeException("Unsupported grant type: " + request.getGrant_type());
	}

	@ResponseStatus(code = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(UnsupportedGrantTypeException.class)
	public TokenError handleUnsupportedGrantType() {
		return new TokenError("Unsupported grant type", "invalid_request");
	}

	@ResponseStatus(code = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(TokenNotFoundException.class)
	public TokenError handleTokenNotFound() {
		return new TokenError("Unable to get access token", "invalid_request");
	}

	private Token createTokenWithAuthorizationCode(TokenRequest request) throws TokenNotFoundException {
		String refreshToken = identityService.getIdWithCode(request.getCode());
		if (refreshToken == null) {
			throw new TokenNotFoundException();
		}
		return createToken(request, refreshToken);
	}

	private Token createTokenWithRefreshToken(TokenRequest request) throws TokenNotFoundException {
		return createToken(request, request.getRefresh_token());
	}

	private Token createToken(TokenRequest request, String refreshToken) throws TokenNotFoundException {
		Identity identity = identityService.getIdentity(refreshToken);
		if (identity == null) {
			throw new TokenNotFoundException();
		}
		Instant now = Instant.now();
		Duration expiresIn = Duration.ofSeconds(providerConfiguration.getAccessTokenExpire());
		String accessToken = createAccessToken(identity, now, expiresIn);
		return new Token(null, accessToken, refreshToken, request.getGrant_type(), (int) expiresIn.getSeconds());
	}

	private String createAccessToken(Identity identity, Instant now, Duration expiresIn) {
		Algorithm algorithm = getAlgorithm(providerConfiguration.getSignatureAlgorithm());
		Builder accessTokenBuilder = JWT.create().withIssuer(providerConfiguration.getIssuerName())
				.withSubject(identity.getSubject()).withClaim("name", identity.getName())
				.withArrayClaim("groupIds", new String[] { identity.getGroupId() }).withIssuedAt(Date.from(now))
				.withExpiresAt(Date.from(now.plus(expiresIn)));
		if (providerConfiguration.isAudiences()) {
			accessTokenBuilder = accessTokenBuilder.withAudience(providerConfiguration.getAudiences());
		}
		return accessTokenBuilder.sign(algorithm);
	}

	private Algorithm getAlgorithm(String signatureAlgorithm) {
		Algorithm algorithm;
		try {
			if ("RS256".equalsIgnoreCase(signatureAlgorithm)) {
				algorithm = getRS256Algorithm();
			} else if ("HS256".equalsIgnoreCase(signatureAlgorithm)) {
				algorithm = getHS256Algorithm();
			} else {
				throw new NoSuchAlgorithmException("Unsupported algorithm: " + signatureAlgorithm);
			}
		} catch (Exception exception) {
			throw new IllegalStateException("Could not initialize requested signing algorithm", exception);
		}
		return algorithm;
	}

	private Algorithm getRS256Algorithm() throws KeyException {
		String keyId = keyService.getKeyId();
		KeyPair keyPair = keyService.getKeyPair();
		return Algorithm.RSA256(new RSAKeyProvider() {
			@Override
			public RSAPublicKey getPublicKeyById(String keyId) {
				return (RSAPublicKey) keyPair.getPublic();
			}

			@Override
			public String getPrivateKeyId() {
				return keyId;
			}

			@Override
			public RSAPrivateKey getPrivateKey() {
				return (RSAPrivateKey) keyPair.getPrivate();
			}
		});
	}

	private Algorithm getHS256Algorithm() throws KeyException, IllegalArgumentException, UnsupportedEncodingException {
		return Algorithm.HMAC256(keyService.getSecretKey());
	}
}