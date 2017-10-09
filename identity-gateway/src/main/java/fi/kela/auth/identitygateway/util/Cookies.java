package fi.kela.auth.identitygateway.util;

import java.util.Arrays;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class Cookies {
	public static Cookie getCookie(HttpServletRequest req, String name) {
		Cookie[] cookies = req.getCookies();
		if (cookies == null) {
			return null;
		}
		return Arrays.asList(cookies).stream().filter(c -> name.equals(c.getName())).findFirst().orElse(null);
	}
}
