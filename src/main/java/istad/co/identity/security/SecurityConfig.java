package istad.co.identity.security;

import istad.co.identity.domain.User;
import istad.co.identity.features.authority.AuthorityRepository;
import istad.co.identity.features.user.OAuth2LoginSuccessHandler;
import istad.co.identity.features.user.UserAuthorityRepository;
import istad.co.identity.features.user.UserRepository;
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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final UserAuthorityRepository userAuthorityRepository;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;


    @Bean
    WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

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
                        .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/login?success=true", false)
                        .failureUrl("/login?error=true")
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureHandler((request, response, exception) -> {
                            log.error("OAuth2 authentication failed: ", exception);
                            response.sendRedirect("/login?error=oauth2");
                        })
                )
//                .oauth2Login(oauth2 -> oauth2
//                        .loginPage("/login")
//                        .defaultSuccessUrl("/login?success=true", false)
//
//                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("https://cloudinator.istad.co")
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .deleteCookies("SESSION")
                        .addLogoutHandler(new SecurityContextLogoutHandler())
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication authentication = context.getPrincipal();
            Object principal = authentication.getPrincipal();

            if (context.getTokenType().getValue().equals("id_token") ||
                    context.getTokenType().getValue().equals("access_token")) {

                // Add standard claims for access tokens
                if (context.getTokenType().getValue().equals("access_token")) {
                    addStandardClaims(context, authentication);
                }

                // Handle different types of principals
                if (principal instanceof CustomUserDetails customUserDetails) {
                    addCustomUserClaims(context, customUserDetails);
                } else if (principal instanceof OAuth2User oauth2User) {
                    // Get the client registration ID
                    String registrationId = null;
                    if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
                        registrationId = oauth2Token.getAuthorizedClientRegistrationId();
                    }

                    // Add claims based on provider
                    switch (registrationId) {
                        case "google" -> addGoogleUserClaims(context, oauth2User);
                        case "github" -> {
                            if (oauth2User.getAttributes().containsKey("login")) {
                                addGithubUserClaims(context, oauth2User);
                            }
                        }
                        case "gitlab" -> addGitLabUserClaims(context, oauth2User);
                    }
                }
            }
        };
    }

    private void addGoogleUserClaims(JwtEncodingContext context, OAuth2User user) {
        Map<String, Object> claims = new HashMap<>();
        String googleId = user.getAttribute("sub");

        User user1 = userRepository.findByUsername(googleId).orElse(null);

        if (user1 != null) {
            claims.put("userUuid", user1.getUuid());
            claims.put("username", user1.getUsername());
            claims.put("email", user.getAttribute("email"));
        }
        if (user.getAttribute("name") != null) {
            claims.put("fullName", user.getAttribute("name"));
        }
        if (user.getAttribute("picture") != null) {
            claims.put("profileImage", user.getAttribute("picture"));
        }

        claims.forEach((key, value) -> context.getClaims().claim(key, value));
    }

    private void addGithubUserClaims(JwtEncodingContext context, OAuth2User user) {
        Map<String, Object> claims = new HashMap<>();
        String githubId = user.getAttribute("id").toString();

        User user1 = userRepository.findByUsername(githubId).orElse(null);

        if (user1 != null) {
            claims.put("userUuid", user1.getUuid());
            claims.put("username", user1.getUsername());
            claims.put("email", user.getAttribute("login") + "@github.com");
        }
        if (user.getAttribute("name") != null) {
            claims.put("fullName", user.getAttribute("name"));
        }
        if (user.getAttribute("avatar_url") != null) {
            claims.put("profileImage", user.getAttribute("avatar_url"));
        }

        claims.forEach((key, value) -> context.getClaims().claim(key, value));
    }

    private void addGitLabUserClaims(JwtEncodingContext context, OAuth2User user) {
        Map<String, Object> claims = new HashMap<>();
        String gitlabId = user.getAttribute("sub");

        User user1 = userRepository.findByUsername(gitlabId).orElse(null);

        if (user1 != null) {
            claims.put("userUuid", user1.getUuid());
            claims.put("username", user1.getUsername());
            claims.put("email", user.getAttribute("email"));
        }
        if (user.getAttribute("name") != null) {
            claims.put("fullName", user.getAttribute("name"));
        }
        if (user.getAttribute("picture") != null) {
            claims.put("profileImage", user.getAttribute("picture"));
        }

        claims.forEach((key, value) -> context.getClaims().claim(key, value));
    }

    private void addStandardClaims(JwtEncodingContext context, Authentication authentication) {
        Set<String> scopes = new HashSet<>(context.getAuthorizedScopes());
        authentication.getAuthorities()
                .forEach(auth -> scopes.add(auth.getAuthority()));
        context.getClaims()
                .id(authentication.getName())
                .subject(authentication.getName())
                .claim("scope", scopes);
    }

    private void addCustomUserClaims(JwtEncodingContext context, CustomUserDetails user) {
        context.getClaims()
                .claim("userUuid", user.getUser().getUuid())
                .claim("username", user.getUser().getUsername())
                .claim("email", user.getUser().getEmail());
    }
}