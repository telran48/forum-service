package telran.java48.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import lombok.RequiredArgsConstructor;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationConfiguration {
	
	final ExpiredPasswordFilter expiredPasswordFilter;

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.httpBasic(Customizer.withDefaults());
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilterBefore(expiredPasswordFilter, AuthorizationFilter.class);
		http.authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/account/register", "/forum/posts/**")
					.permitAll()
				.requestMatchers("/account/user/{login}/role/{role}")
					.hasRole("ADMINISTRATOR")
				.requestMatchers(HttpMethod.PUT, "/account/user/{login}")
					.access(new WebExpressionAuthorizationManager("#login == authentication.name"))
				.requestMatchers(HttpMethod.DELETE, "/account/user/{login}")
					.access(new WebExpressionAuthorizationManager("#login == authentication.name or hasRole('ADMINISTRATOR')"))
				.requestMatchers(HttpMethod.POST, "/forum/post/{author}")
        			.access(new WebExpressionAuthorizationManager("#author == authentication.name"))
        		.requestMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}")
        			.access(new WebExpressionAuthorizationManager("#author == authentication.name"))
        		.requestMatchers(HttpMethod.PUT, "/forum/post/{id}")
        			.access(new WebExpressionAuthorizationManager("@customSecurity.checkPostAuthor(#id, authentication.name)"))
        		.requestMatchers(HttpMethod.DELETE, "/forum/post/{id}")
        			.access(new WebExpressionAuthorizationManager("@customSecurity.checkPostAuthor(#id, authentication.name) or hasRole('MODERATOR')"))
				.anyRequest()
					.authenticated()
		);
		return http.build();
	}
	
	@Bean
	public FilterRegistrationBean<ExpiredPasswordFilter> expiredPasswordFilterRegistration(ExpiredPasswordFilter filter) {
	    FilterRegistrationBean<ExpiredPasswordFilter> registration = new FilterRegistrationBean<>(filter);
	    registration.setEnabled(false);
	    return registration;
	}
}
