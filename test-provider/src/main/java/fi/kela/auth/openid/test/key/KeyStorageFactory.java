package fi.kela.auth.openid.test.key;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import fi.kela.auth.openid.test.config.ProviderConfiguration;

@Component
public class KeyStorageFactory {
	private static final Logger logger = Logger.getLogger(KeyStorageFactory.class);
	private ProviderConfiguration providerConfiguration;
	private KeyGenerator keyGenerator;
	private KeyFactory rsaKeyFactory;

	public KeyStorageFactory(ProviderConfiguration providerConfiguration, KeyGenerator keyGenerator) {
		this.providerConfiguration = providerConfiguration;
		this.keyGenerator = keyGenerator;
		try {
			this.rsaKeyFactory = KeyFactory.getInstance("RSA");
		} catch (Exception exception) {
			throw new IllegalStateException("Could not initialize RSA");
		}
	}

	@Bean
	public KeyStorage getGetKeyStorage() throws KeyException {
		KeyPair keyPair;
		if (isKeyPairConfigured()) {
			keyPair = getKeyPairFromConfiguration();
		} else {
			logger.info("KeyPair is not set, generating random key");
			keyPair = keyGenerator.generateRSAKeyPair();
		}
		return new SimpleKeyStorage(providerConfiguration.getSecretKey(), keyPair);
	}

	private KeyPair getKeyPairFromConfiguration() throws KeyException {
		KeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				Base64.getDecoder().decode(providerConfiguration.getPrivateKey()));
		KeySpec publicKeySpec = new X509EncodedKeySpec(
				Base64.getDecoder().decode(providerConfiguration.getPublicKey()));
		try {
			return new KeyPair((RSAPublicKey) rsaKeyFactory.generatePublic(publicKeySpec),
					(RSAPrivateKey) rsaKeyFactory.generatePrivate(privateKeySpec));
		} catch (Exception exception) {
			throw new KeyException("Could not load keypair", exception);
		}
	}

	private boolean isKeyPairConfigured() {
		return providerConfiguration.getPrivateKey() != null && providerConfiguration.getPublicKey() != null;
	}
}