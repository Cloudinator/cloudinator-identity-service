package istad.co.identity.security;

import istad.co.identity.security.custom.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {


    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;


    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        return authenticationProvider;
    }


    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


    @Bean
    @Order(1)
    SecurityFilterChain configureOAuth2(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                /*.authorizationEndpoint(endpoint -> endpoint
                        .consentPage("/oauth2/consent")
                )*/
                .oidc(Customizer.withDefaults());

        http
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );


        return http.build();
    }


    @Bean
    @Order(2)
    SecurityFilterChain configureHttpSecurity(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest()
                        .permitAll()
                )

                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
//                .formLogin(Customizer.withDefaults())
                /*.formLogin(form -> form
                        .loginPage("/oauth2/login")
                        .usernameParameter("gp_account")
                        .passwordParameter("gp_password")
                )*/
                .formLogin(form -> form
                                .loginPage("/login")  // Custom login page URL
                                .loginProcessingUrl("/login")  // Where the login form posts to
                                .usernameParameter("username")  // Default username parameter is 'username'
                                .passwordParameter("password")  // Default password parameter is 'password'
                                .failureUrl("/login?error=true")  // URL to redirect to in case of login failure
                                .defaultSuccessUrl("/login?success=true", false)

//                        .successForwardUrl("http://localhost:8000")
                ) // Redirect on success
                .logout(logout -> logout
                        .logoutUrl("/logout")  // The logout URL
                        .invalidateHttpSession(true)  // Invalidate the session
                        .clearAuthentication(true)
                        .deleteCookies("access_token", "JSESSIONID")  // Clear the OAuth2 token and session cookie
                        .logoutSuccessUrl("http://34.87.156.153:8081?logout=true")
                )
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }


    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {

            // TODO: Custom JWT with authorization_code grant type and Authentication
            Authentication authentication = context.getPrincipal();
            CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

            if (context.getTokenType().getValue().equals("id_token")) {
                context.getClaims()
                        .claim("userId", customUserDetails.getUser().getUuid())        // User UUID
                        .claim("username", customUserDetails.getUser().getUsername());  // User Full Name;
            }

            if (context.getTokenType().getValue().equals("access_token")) {
                Set<String> scopes = new HashSet<>(context.getAuthorizedScopes());
                authentication
                        .getAuthorities()
                        .forEach(grantedAuthority -> scopes.add(grantedAuthority.getAuthority()));
                context.getClaims()
                        .id(authentication.getName())
                        .subject(authentication.getName())
                        .claim("scope", scopes)
                        .claim("uuid", customUserDetails.getUser().getUuid());
            }
        };
    }


    /*@Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {

        Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = jwt -> {
            Collection<String> scopes = jwt.getClaimAsStringList("scope");

            scopes.forEach(s -> log.info("Scope: {}", s));

            return scopes.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        };

        var jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }*/

}

