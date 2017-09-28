package fi.kela.auth.openid.test.identity;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Controller;

@Controller
public class IdentityService {
	private static final Map<String, Identity> identities = new ConcurrentHashMap<>();

	public String storeIdentity(Identity identity) {
		// TODO: Expiration would increase security and prevent overflow :-)
		String id = generateUniqueId();
		identities.put(id, identity);
		return id;
	}

	public Identity getIdentity(String id) {
		return identities.get(id);
	}

	private String generateUniqueId() {
		return UUID.randomUUID().toString().replace("-", "");
	}
}
