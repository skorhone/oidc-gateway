package fi.kela.auth.openid.test.key;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import fi.kela.auth.openid.test.jwk.JWK;
import fi.kela.auth.openid.test.jwk.JWKS;

public class SimpleKeyStorage implements KeyStorage {
	private String secret;
	private KeyPair keyPair;
	private String kid;

	public SimpleKeyStorage(String secret, KeyPair keyPair) throws KeyException {
		this.secret = secret;
		this.keyPair = keyPair;
		this.kid = keyPair != null ? hash(keyPair.getPublic()) : null;
	}

	@Override
	public String getSecretKey() throws KeyException {
		if (secret == null) {
			throw new KeyException("Secret key is not set");
		}
		return secret;
	}
	
	@Override
	public String getKeyId() throws KeyException {
		if (kid == null) {
			throw new KeyException("Key id is not set");
		}
		return this.kid;
	}

	@Override
	public KeyPair getKeyPair() throws KeyException {
		if (keyPair == null) {
			throw new KeyException("Key pair is not set");
		}
		return keyPair;
	}

	@Override
	public JWKS getJWKS() throws KeyException {
		KeyPair keyPair = getKeyPair();
		List<JWK> keys = new ArrayList<>();
		if (keyPair != null) {
			if ("RSA".equals(keyPair.getPublic().getAlgorithm())) {
				keys.add(JWK.of(kid, (RSAPublicKey) keyPair.getPublic()));
			}
		}
		return new JWKS(keys);
	}

	private String hash(PublicKey publicKey) throws KeyException {
		return hash(publicKey.getEncoded());
	}

	private String hash(byte[] key) throws KeyException {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return Base64.getEncoder().encodeToString(digest.digest(key));
		} catch (Exception exception) {
			throw new KeyException("Could not hash key", exception);
		}
	}
}
