package com.microsoft.azure.aad.security;

import com.microsoft.azure.spring.autoconfigure.aad.AADAuthenticationFailureHandler;
import com.microsoft.azure.spring.autoconfigure.aad.AADOAuth2AuthorizationRequestResolver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.reactive.function.client.WebClient;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AADOAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;

	@Autowired
	ApplicationContext applicationContext;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		final ClientRegistrationRepository clientRegistrationRepository =
				applicationContext.getBean(ClientRegistrationRepository.class);
		http.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				.oauth2Login()
				.userInfoEndpoint()
				.oidcUserService(oidcUserService)
				.and()
				.authorizationEndpoint()
				.authorizationRequestResolver(
						new AADOAuth2AuthorizationRequestResolver(clientRegistrationRepository))
				.and()
				.failureHandler(new AADAuthenticationFailureHandler());
	}

	@Bean
	WebClient webClient(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository) {
		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrationRepository, authorizedClientRepository);
		oauth2.setDefaultOAuth2AuthorizedClient(true);
		return WebClient.builder()
				.apply(oauth2.oauth2Configuration())
				.build();
	}
}
