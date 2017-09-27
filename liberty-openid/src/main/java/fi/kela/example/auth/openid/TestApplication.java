package fi.kela.example.auth.openid;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Principal;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/hello")
public class TestApplication extends HttpServlet {
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		try (OutputStream os = res.getOutputStream()) {
			Principal principal = req.getUserPrincipal();
			String name;
			if (principal != null) {
				name = principal.toString();
			} else {
				name = "Unknown Dude";
			}
			os.write(new StringBuilder("Hello ").append(name).append('!').toString().getBytes("utf-8"));
		}
	}
}
