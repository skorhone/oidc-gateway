package fi.kela.auth.identitygateway.oidcclient.key;

import java.security.interfaces.RSAPublicKey;

public interface KeyProvider {
	public RSAPublicKey getRSAPublicKey(String kid);
}
