package telran.java48.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class AuthorizationConfiguration {

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.httpBasic(Customizer.withDefaults());
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilterAfter(new ExpiredPasswordFilter(), BasicAuthenticationFilter.class);
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
}
