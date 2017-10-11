package fi.kela.auth.identitygateway.oidcclient.key;

import java.security.interfaces.RSAPublicKey;

public class NoKeyProvider implements KeyProvider {
	@Override
	public RSAPublicKey getRSAPublicKey(String kid) {
		throw new KeyException("Public key provider is not configured");
	}
}
