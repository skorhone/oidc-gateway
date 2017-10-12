package fi.kela.auth.openid.test.identity;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;

import fi.kela.auth.openid.test.config.ProviderConfiguration;

@Service
public class IdentityService {
	private ProviderConfiguration providerConfiguration;
	private Map<String, Identity> codeIdentities;
	private Map<String, Identity> tokenIdentities;

	public IdentityService(ProviderConfiguration providerConfiguration) {
		this.providerConfiguration = providerConfiguration;
		this.codeIdentities = new ConcurrentHashMap<>(1000);
		this.tokenIdentities = new ConcurrentHashMap<>(1000);
	}

	/**
	 * Store identity
	 * 
	 * @param identity
	 *            identity
	 * @return code
	 */
	public String storeIdentity(Identity identity) {
		String code = generateUniqueId();
		codeIdentities.put(code, identity);
		return code;
	}

	/**
	 * Invalidate the given code and return storage id
	 * 
	 * @param id
	 *            storage id
	 * @return storage id
	 */
	public String getIdWithCode(String code) {
		Identity identity = codeIdentities.remove(code);
		if (identity == null) {
			return null;
		}
		String id = generateUniqueId();
		identity.setExpiresAt(
				System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(providerConfiguration.getRefreshTokenExpire()));
		tokenIdentities.put(id, identity);
		return id;
	}

	/**
	 * Get identity
	 * 
	 * @param id
	 *            storage id
	 * @return identity (if any)
	 */
	public Identity getIdentity(String id) {
		Identity identity = tokenIdentities.get(id);
		if (identity != null && identity.isExpired()) {
			tokenIdentities.remove(id);
			identity = null;
		}
		return identity;
	}

	private String generateUniqueId() {
		return UUID.randomUUID().toString().replace("-", "");
	}
}