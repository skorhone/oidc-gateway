package fi.kela.auth.openid.test.key;

import java.security.KeyPair;

import org.springframework.stereotype.Service;

import fi.kela.auth.openid.test.jwk.JWKS;

@Service
public class KeyService {
	private KeyStorage keyStorage;

	public KeyService(KeyStorage keyStorage) {
		this.keyStorage = keyStorage;
	}

	public String getSecretKey() throws KeyException {
		return keyStorage.getSecretKey();
	}
	
	public String getKeyId() throws KeyException {
		return keyStorage.getKeyId();
	}

	public KeyPair getKeyPair() throws KeyException {
		return keyStorage.getKeyPair();
	}

	public JWKS getJWKS() throws KeyException {
		return keyStorage.getJWKS();
	}
}
