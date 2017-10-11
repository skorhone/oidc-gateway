package fi.kela.auth.identitygateway.oidcclient.key;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import fi.kela.auth.identitygateway.oidcclient.OIDCConfiguration;
import fi.kela.auth.identitygateway.oidcclient.key.jwk.JWKSKeyProvider;

@Component
public class KeyProviderFactory {
	@Bean
	public KeyProvider createKeyProvider(OIDCConfiguration oidcConfiguration) {
		if (oidcConfiguration.getJwksProvider() != null) {
			return new JWKSKeyProvider(oidcConfiguration.getJwksProvider());
		}
		if (oidcConfiguration.getPublicKey() != null) {
			return FixedKeyProvider.of(oidcConfiguration.getPublicKey());
		}
		return new NoKeyProvider();
	}
}
