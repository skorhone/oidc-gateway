package fi.kela.auth.openid.test.wellknown;

import org.apache.log4j.Logger;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import fi.kela.auth.openid.test.jwk.JWKS;
import fi.kela.auth.openid.test.key.KeyException;
import fi.kela.auth.openid.test.key.KeyService;

@RestController
public class WellknownController {
	private static final Logger logger = Logger.getLogger(WellknownController.class);
	private KeyService keyService;

	public WellknownController(KeyService keyService) {
		this.keyService = keyService;
	}

	@RequestMapping(value = "/.well-known/jwks.json", method = RequestMethod.GET)
	public JWKS getJWKS() throws KeyException {
		logger.info("Processing key request");
		return keyService.getJWKS();
	}
}