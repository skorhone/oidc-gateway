package fi.kela.auth.openid.test.token;

import java.io.UnsupportedEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import fi.kela.auth.openid.test.identity.Identity;
import fi.kela.auth.openid.test.identity.IdentityService;

@RestController
public class TokenController {
	@Autowired
	private IdentityService identityService;

	@RequestMapping(value = "/token", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public Token createToken(TokenRequest request) throws UnsupportedEncodingException {
		if ("authorization_code".equals(request.getGrant_type())) {
			return createTokenWithAuthorizationCode(request);
		}
		if ("refresh_token".equals(request.getGrant_type())) {
			return createTokenWithRefreshToken(request);
		}
		throw new IllegalArgumentException("Unsupported grant type: " + request.getGrant_type());
	}

	private Token createTokenWithAuthorizationCode(TokenRequest request) throws UnsupportedEncodingException {
		Identity identity = identityService.getIdentity(request.getCode());
		return createTokenUsingIdentity(request, identity);
	}

	private Token createTokenWithRefreshToken(TokenRequest request) throws UnsupportedEncodingException {
		Identity identity = identityService.getIdentity(request.getRefresh_token());
		return createTokenUsingIdentity(request, identity);
	}

	private Token createTokenUsingIdentity(TokenRequest request, Identity identity)
			throws UnsupportedEncodingException {
		String refreshToken = createRefreshToken(identity);
		Instant now = Instant.now();
		Algorithm algorithm = Algorithm.HMAC256("secret");
		Duration expiresIn = Duration.ofHours(2);
		String jwt = JWT.create().withIssuer("https://openid.kela.fi").withSubject(identity.getSubject())
				.withClaim("name", identity.getName())
				.withArrayClaim("groupIds", new String[] { identity.getGroupId() }).withIssuedAt(Date.from(now))
				.withExpiresAt(Date.from(now.plus(expiresIn))).withAudience("https://kela.fi").sign(algorithm);
		return new Token(jwt, "access_token", refreshToken, request.getGrant_type(), (int) expiresIn.getSeconds());
	}

	private String createRefreshToken(Identity identity) {
		return identityService.storeIdentity(identity);
	}
}