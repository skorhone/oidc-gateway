package fi.kela.auth.openid.test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableAutoConfiguration
public class AuthApplication {
	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

	@Bean
	public ServletRegistrationBean getLoginServlet() {
		return new ServletRegistrationBean(new LoginServlet(), "/login");
	}

	@Bean
	public ServletRegistrationBean getTokenServlet() {
		return new ServletRegistrationBean(new TokenServlet(), "/token");
	}
}