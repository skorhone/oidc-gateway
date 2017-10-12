package fi.kela.auth.identitygateway.oidcclient.key;

import java.net.URL;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import fi.kela.auth.identitygateway.json.JSONService;
import fi.kela.auth.identitygateway.oidcclient.OIDCConfiguration;
import fi.kela.auth.identitygateway.oidcclient.key.jwk.JWKSKeyProvider;

@Component
public class KeyProviderFactory {
	private static final Logger logger = Logger.getLogger(KeyProviderFactory.class);

	@Bean
	public KeyProvider createKeyProvider(OIDCConfiguration oidcConfiguration, JSONService jsonService) {
		if (oidcConfiguration.getJwksProvider() != null) {
			return createJWKSKeyProvider(oidcConfiguration, jsonService);
		}
		if (oidcConfiguration.getPublicKey() != null) {
			return createFixedKeyProvider(oidcConfiguration);
		}
		return new NoKeyProvider();
	}

	private KeyProvider createFixedKeyProvider(OIDCConfiguration oidcConfiguration) {
		return FixedKeyProvider.of(oidcConfiguration.getPublicKey());
	}

	private KeyProvider createJWKSKeyProvider(OIDCConfiguration oidcConfiguration, JSONService jsonService) {
		try {
			URL providerURL = new URL(oidcConfiguration.getJwksProvider());
			long jwksReloadAfter = oidcConfiguration.getJwksReloadAfter();
			if (jwksReloadAfter <= 0) {
				jwksReloadAfter = TimeUnit.MINUTES.toSeconds(15);
			}
			validateURL(providerURL);
			return new JWKSKeyProvider(providerURL, jsonService, TimeUnit.SECONDS.toMillis(jwksReloadAfter));
		} catch (Exception exception) {
			throw new KeyException("Invalid jwks provider url: " + oidcConfiguration.getJwksProvider());
		}
	}

	private void validateURL(URL url) {
		if (!url.getProtocol().endsWith("s")) {
			logger.warn("Unsafe jwks provider url: " + url.toExternalForm());
		}
	}
}
