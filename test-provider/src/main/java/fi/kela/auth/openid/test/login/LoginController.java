package fi.kela.auth.openid.test.login;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import fi.kela.auth.openid.test.identity.Identity;
import fi.kela.auth.openid.test.identity.IdentityService;

@Controller
public class LoginController {
	private static final String ENCODING = "utf-8";
	private String[] validClientIds = { "kela" };
	@Autowired
	private IdentityService identityService;

	@GetMapping("/login")
	public String login(@RequestParam(value = "response_type", required = true) String responseType,
			@RequestParam(value = "scope", required = true) String scope,
			@RequestParam(value = "client_id", required = true) String clientId,
			@RequestParam(value = "state", required = true) String state,
			@RequestParam(value = "redirect_uri", required = true) String redirectURI, Model model) {
		if (!"code".equals(responseType) || !Arrays.asList(validClientIds).contains(clientId) || state.isEmpty()
				|| redirectURI.isEmpty()) {
			return "error";
		}
		Login login = new Login();
		login.setResponseType(responseType);
		login.setClientId(clientId);
		login.setState(state);
		login.setRedirectURI(redirectURI);

		model.addAttribute("login", login);
		return "login";
	}

	@PostMapping("/login")
	public String loginSubmit(@ModelAttribute Login login) {
		try {
			String code = identityService.storeIdentity(
					new Identity(login.getRedirectURI(), login.getSubject(), login.getName(), login.getGroupId()));
			return "redirect:" + login.getRedirectURI() + "?code=" + URLEncoder.encode(code, ENCODING) + "&state="
					+ URLEncoder.encode(login.getState(), ENCODING);
		} catch (UnsupportedEncodingException exception) {
			return "error";
		}
	}
}
