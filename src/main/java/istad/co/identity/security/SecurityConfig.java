package istad.co.identity.security;


import istad.co.identity.domain.User;
import istad.co.identity.domain.UserAuthority;
import istad.co.identity.features.authority.AuthorityRepository;
import istad.co.identity.features.user.UserAuthorityRepository;
import istad.co.identity.features.user.UserRepository;
import istad.co.identity.security.custom.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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


//    @Bean
//    @Order(2)
//    SecurityFilterChain configureHttpSecurity(HttpSecurity http) throws Exception {
////
////        http
////                .authorizeHttpRequests(auth -> auth
////                        .anyRequest().permitAll()
////                )
////
////                .oauth2ResourceServer(oauth2 -> oauth2
////                        .jwt(Customizer.withDefaults())
////                )
////                .oauth2Login(Customizer.withDefaults())
////                .formLogin(Customizer.withDefaults())
//////                .formLogin(form -> form
//////                        .loginPage("/oauth2/login")
//////                        .usernameParameter("gp_account")
//////                        .passwordParameter("gp_password")
//////                )
////                .cors(AbstractHttpConfigurer::disable)
////                .csrf(AbstractHttpConfigurer::disable);
////
////        return http.build();
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/login","/login/oauth2/code/*", "/oauth2/**", "/error", "/register", "/otp/**", "/resend-otp", "/forget-password", "/reset-pwd-otp", "/reset-password", "/google", "http://localhost:8168", "/github","/facebook").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .formLogin(form -> form
//                                .loginPage("/login")
//                                .loginProcessingUrl("/login")
//                        .defaultSuccessUrl("http://localhost:8168/", true)
//                                .failureUrl("/login?error=true")
//                )
//                .oauth2Login(oauth2 -> oauth2
//                        .loginPage("/login")
//                        .defaultSuccessUrl("http://localhost:8888/", true)
//                )
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(Customizer.withDefaults())
//                )
//                .logout(logout -> logout
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                        .logoutSuccessUrl("http://127.0.0.1:8168")
//                )
//                .cors(AbstractHttpConfigurer::disable)
//                .csrf(AbstractHttpConfigurer::disable);
//
//        return http.build();
//    }
@Bean
@Order(2)
SecurityFilterChain configureHttpSecurity(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(auth -> auth
                    .anyRequest().authenticated()
            )
            .formLogin(form -> form
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .defaultSuccessUrl("/login?success=true", false)// Change this
                    .failureUrl("/login?error=true")
            )
            .oauth2Login(oauth2 -> oauth2
                    .loginPage("/login")
                    .defaultSuccessUrl("/login?success=true", false)
                    .userInfoEndpoint(userInfo -> userInfo
                            .userService(oauth2UserService())
                    )
                    .failureHandler((request, response, exception) -> {
                        log.error("OAuth2 authentication failed: ", exception);
                        response.sendRedirect("/login?error=oauth2");
                    })
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(Customizer.withDefaults())
            )
            .logout(logout -> logout
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("http://localhost:8888?logout=true")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
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

            if (context.getTokenType().getValue().equals("id_token")) {
                if (principal instanceof CustomUserDetails customUserDetails) {
                    addCustomUserClaims(context, customUserDetails);
                } else if (principal instanceof DefaultOidcUser oidcUser) {
                    addGoogleUserClaims(context, oidcUser);
                } else if (principal instanceof DefaultOAuth2User oauth2User) {
                    addGithubUserClaims(context, oauth2User);
                }
            }

            if (context.getTokenType().getValue().equals("access_token")) {
                addStandardClaims(context, authentication);

                if (principal instanceof CustomUserDetails customUserDetails) {
                    addCustomUserClaims(context, customUserDetails);
                } else if (principal instanceof DefaultOidcUser oidcUser) {
                    addGoogleUserClaims(context, oidcUser);
                } else if (principal instanceof DefaultOAuth2User oauth2User) {
                    addGithubUserClaims(context, oauth2User);
                }
            }
        };
    }
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        return userRequest -> {
            OAuth2User oauth2User = delegate.loadUser(userRequest);
            String registrationId = userRequest.getClientRegistration().getRegistrationId();

            if ("google".equals(registrationId)) {
                String email = oauth2User.getAttribute("email");
                String name = oauth2User.getAttribute("name");
                String picture = oauth2User.getAttribute("picture");

                try {
                    return userRepository.findByEmail(email)
                            .map(existingUser -> oauth2User)  // If user exists, return original oauth2User
                            .orElseGet(() -> {
                                // Create new user
                                User user = User.builder()
                                        .uuid(UUID.randomUUID().toString())
                                        .username(generateUniqueUsername(oauth2User.getAttribute("name")))
                                        .email(email)
                                        .profileImage(oauth2User.getAttribute("picture"))
                                        .emailVerified(true)
                                        .accountNonExpired(true)
                                        .accountNonLocked(true)
                                        .credentialsNonExpired(true)
                                        .isEnabled(true)
                                        .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                                        .build();

                                user = userRepository.save(user);
                                addDefaultUserAuthority(user);
                                return oauth2User;
                            });
                } catch (Exception e) {
                    log.error("Error creating Google user:", e);
                    throw new OAuth2AuthenticationException(
                            new OAuth2Error("user_creation_error", "Could not create user", null)
                    );
                }
            } else if ("github".equals(registrationId)) {
                String login = oauth2User.getAttribute("login");
                String name = oauth2User.getAttribute("name");
                String avatarUrl = oauth2User.getAttribute("avatar_url");
                String email = login + "istad@github.com";

                try {
                    return userRepository.findByEmail(email)
                            .map(existingUser -> oauth2User)  // If user exists, return original oauth2User
                            .orElseGet(() -> {
                                // Create new user
                                User user = User.builder()
                                        .uuid(UUID.randomUUID().toString())
                                        .username(generateUniqueUsername(oauth2User.getAttribute("name")))
                                        .email(email)
                                        .profileImage(oauth2User.getAttribute("picture"))
                                        .emailVerified(true)
                                        .accountNonExpired(true)
                                        .accountNonLocked(true)
                                        .credentialsNonExpired(true)
                                        .isEnabled(true)
                                        .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                                        .build();

                                user = userRepository.save(user);
                                addDefaultUserAuthority(user);
                                return oauth2User;
                            });
                } catch (Exception e) {
                    log.error("Error creating Google user:", e);
                    throw new OAuth2AuthenticationException(
                            new OAuth2Error("user_creation_error", "Could not create user", null)
                    );
                }
            }

            return oauth2User;
        };
    }

    private String generateUsername(String email) {
        String baseUsername = email.split("@")[0];
        String username = baseUsername;
        int counter = 1;

        while (userRepository.existsByUsername(username)) {
            username = baseUsername + counter++;
        }

        return username;
    }

    private void addDefaultUserAuthority(User user) {
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.findByName("USER")
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "USER authority not found")));

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);

        // Add OAuth2 authority
        UserAuthority oauth2Authority = new UserAuthority();
        oauth2Authority.setUser(user);
        oauth2Authority.setAuthority(authorityRepository.findByName("OAUTH2_USER")
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "OAUTH2_USER authority not found")));
        user.getUserAuthorities().add(oauth2Authority);

        userAuthorityRepository.saveAll(user.getUserAuthorities());
    }
    private void addStandardClaims(JwtEncodingContext context, Authentication authentication) {
        Set<String> scopes = new HashSet<>(context.getAuthorizedScopes());

        // Add a default USER role for OAuth2 users
        if (authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("OAUTH2_USER"))) {
            scopes.add("USER");
        }

        // Add other authorities
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
//                .claim("fullName", user.getUser().getFullName())
                .claim("email", user.getUser().getEmail());
    }

    private void addGoogleUserClaims(JwtEncodingContext context, DefaultOidcUser user) {
        String email = user.getEmail();
        userRepository.findByEmail(email)
                .ifPresentOrElse(
                        userEntity -> {
                            context.getClaims()
                                    .claim("userUuid", userEntity.getUuid())
                                    .claim("username", userEntity.getUsername())
//                                    .claim("fullName", userEntity.getFullName())
                                    .claim("profileImage", userEntity.getProfileImage())
                                    .claim("email", userEntity.getEmail());

                        },
                        () -> {
                            context.getClaims()
                                    .claim("email", email)
                                    .claim("fullName", user.getFullName());
                        }
                );

    }

    private void addGithubUserClaims(JwtEncodingContext context, DefaultOAuth2User user) {
        Map<String, Object> claims = new HashMap<>();

        User user1 = userRepository.findByUsername(user.getAttribute("login")).orElse(null);

        if (user1 != null) {
            claims.put("userUuid", user1.getUuid());
            claims.put("username", user1.getUsername());
            claims.put("email", user.getAttribute("login")+ "@github.com");
        }
        if (user.getAttribute("name") != null) {
            claims.put("fullName", user.getAttribute("name"));
        }
        if (user.getAttribute("avatar_url") != null) {
            claims.put("profileImage", user.getAttribute("avatar_url"));
        }

        claims.forEach((key, value) -> context.getClaims().claim(key, value));
    }
    private String generateUniqueUsername(String fullName) {
        // Remove spaces and special characters
        String baseUsername = sanitizeUsername(fullName);

        // If the base username is empty (rare case), use a default
        if (baseUsername.isEmpty()) {
            baseUsername = "user";
        }

        String username = baseUsername;
        int counter = 1;

        // Keep trying until we find a unique username
        while (userRepository.existsByUsername(username)) {
            // Add random numbers to make it more unique
            username = baseUsername + counter + new Random().nextInt(1000);
            counter++;
        }

        return username;
    }
    private String sanitizeUsername(String username) {
        // Remove any whitespace
        username = username.trim().replaceAll("\\s+", "");

        // Convert to proper case (first letter capital, rest lowercase)
        if (!username.isEmpty()) {
            username = username.substring(0, 1).toUpperCase() +
                    username.substring(1).toLowerCase();
        }

        // Remove any special characters
        username = username.replaceAll("[^a-zA-Z0-9]", "");

        return username;
    }
}