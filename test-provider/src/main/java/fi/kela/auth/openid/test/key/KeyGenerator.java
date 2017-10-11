package fi.kela.auth.openid.test.key;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.springframework.stereotype.Component;

@Component
public class KeyGenerator {
	public KeyPair generateRSAKeyPair() throws KeyException {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception exception) {
			throw new KeyException("Could not generate new RSA key pair", exception);
		}
	}
}
