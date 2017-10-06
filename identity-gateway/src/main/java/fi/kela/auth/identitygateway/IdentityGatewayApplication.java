package fi.kela.auth.identitygateway;

import javax.servlet.Servlet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;

@EnableCaching
@SpringBootApplication
@EnableAutoConfiguration
public class IdentityGatewayApplication {
	public static void main(String[] args) {
		SpringApplication.run(IdentityGatewayApplication.class, args);
	}

	@Bean
	public Servlet dispatcherServlet() {
		return new GatewayServlet();
	}
}