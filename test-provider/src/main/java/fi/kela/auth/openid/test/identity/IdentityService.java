package fi.kela.auth.openid.test.identity;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Controller;

@Controller
public class IdentityService {
	// TODO: Expiration would increase security and prevent overflow :-)
	private static final Map<String, Identity> codeIdentities = new ConcurrentHashMap<>(1000);
	private static final Map<String, Identity> tokenIdentities = new ConcurrentHashMap<>(1000);

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
		return tokenIdentities.get(id);
	}

	private String generateUniqueId() {
		return UUID.randomUUID().toString().replace("-", "");
	}
}