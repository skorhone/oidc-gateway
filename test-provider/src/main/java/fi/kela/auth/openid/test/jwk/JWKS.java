package fi.kela.auth.openid.test.jwk;

import java.util.List;

public class JWKS {
	private List<JWK> keys;

	public JWKS(List<JWK> keys) {
		this.keys = keys;
	}

	public List<JWK> getKeys() {
		return keys;
	}
}
