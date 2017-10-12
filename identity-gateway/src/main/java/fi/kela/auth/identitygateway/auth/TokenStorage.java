package fi.kela.auth.identitygateway.auth;

import java.util.UUID;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

import fi.kela.auth.identitygateway.oidcclient.Token;

@Component
public class TokenStorage {
	private Cache tokens;

	public TokenStorage(CacheManager cacheManager) {
		this.tokens = cacheManager.getCache("tokens");
	}

	public String store(Token token) {
		String tokenId = UUID.randomUUID().toString().replace("-", "");
		tokens.put(tokenId, token);
		return tokenId;
	}

	public Token get(String tokenId) {
		return tokens.get(tokenId, Token.class);
	}

	public void update(String tokenId, Token token) {
		tokens.put(tokenId, token);
	}

	public void remove(String tokenId) {
		tokens.evict(tokenId);
	}
}
