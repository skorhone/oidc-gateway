package fi.kela.auth.openid.test.key;

import java.security.KeyPair;

import fi.kela.auth.openid.test.jwk.JWKS;

public interface KeyStorage {
	public String getSecretKey() throws KeyException;
	public String getKeyId() throws KeyException;
	public KeyPair getKeyPair() throws KeyException;
	public JWKS getJWKS() throws KeyException;
}
