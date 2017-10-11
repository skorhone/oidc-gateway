package fi.kela.auth.identitygateway.oidcclient.key.jwk;

import java.util.List;

public class JWKS {
	private List<JWK> keys;

	public List<JWK> getKeys() {
		return keys;
	}
	
	public void setKeys(List<JWK> keys) {
		this.keys = keys;
	}
}
