package fi.kela.auth.identitygateway;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.servlet.Servlet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;

import fi.kela.auth.identitygateway.auth.AuthService;
import fi.kela.auth.identitygateway.proxy.ProxyService;

@EnableCaching
@SpringBootApplication
@EnableAutoConfiguration
public class IdentityGatewayApplication {
	public static void main(String[] args) {
		SpringApplication.run(IdentityGatewayApplication.class, args);
	}

	@Bean
	public Servlet dispatcherServlet(IGWConfiguration igwConfiguration, AuthService authService,
			ProxyService proxyService, ExecutorService executorService) {
		return new GatewayServlet(igwConfiguration, authService, proxyService, executorService);
	}

	@Bean
	@Scope("singleton")
	public ExecutorService executorService() {
		return Executors.newCachedThreadPool();
	}
}