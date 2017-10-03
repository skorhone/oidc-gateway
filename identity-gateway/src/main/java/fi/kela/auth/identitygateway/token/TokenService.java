package fi.kela.auth.identitygateway.token;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import fi.kela.auth.identitygateway.oicclient.Token;

@Service
public class TokenService {
	// TODO: Replace with EHCACHE or something similar?
	private static Map<String, Token> TOKENS = new ConcurrentHashMap<>();

	public String store(Token token) {
		String tokenId = UUID.randomUUID().toString().replace("-", "");
		TOKENS.put(tokenId, token);
		return tokenId;
	}

	public Token get(String tokenId) {
		return TOKENS.get(tokenId);
	}

	public boolean contains(String tokenId) {
		return TOKENS.containsKey(tokenId);
	}
}
