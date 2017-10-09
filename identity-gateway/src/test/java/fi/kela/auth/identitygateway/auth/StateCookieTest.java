package fi.kela.auth.identitygateway.auth;

import static org.junit.Assert.*;

import org.junit.Test;

import fi.kela.auth.identitygateway.auth.StateCookie;

public class StateCookieTest {
	@Test
	public void encode() {
		StateCookie cookie = new StateCookie("&state?", "&origin?");
		String encoded = cookie.toString();
		assertEquals("%26state%3F&%26origin%3F", encoded);
	}

	@Test
	public void decode() {
		StateCookie cookie = StateCookie.of("%26state%3F&%26origin%3F");
		assertEquals("&state?", cookie.getState());
		assertEquals("&origin?", cookie.getOrigin());
	}
}
