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

import fi.kela.auth.identitygateway.oidcclient.OIDCService;
import fi.kela.auth.identitygateway.proxy.ProxyService;
import fi.kela.auth.identitygateway.token.TokenService;

@EnableCaching
@SpringBootApplication
@EnableAutoConfiguration
public class IdentityGatewayApplication {
	public static void main(String[] args) {
		SpringApplication.run(IdentityGatewayApplication.class, args);
	}

	@Bean
	public Servlet dispatcherServlet(IGWConfiguration igwConfiguration, OIDCService oidcService,
			ProxyService proxyService, TokenService tokenService) {
		return new GatewayServlet(igwConfiguration, oidcService, proxyService, tokenService);
	}
	
	@Bean
	@Scope("singleton")
	public ExecutorService executorService() {
		return Executors.newCachedThreadPool();
	}
}