package istad.co.identity.security;


import istad.co.identity.domain.User;
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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {


    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;


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
                    .requestMatchers(
                            "/login",
                            "/login/oauth2/code/*",
                            "/oauth2/**",
                            "/error",
                            "/register",
                            "/otp/**",
                            "/resend-otp",
                            "/forget-password",
                            "/reset-pwd-otp",
                            "/reset-password",
                            "/google",
                            "/facebook",
                            "/github",
                            "/images/**",
                            "/webjars/**",
                            "/me",              // Add these
                            "/user/details",    // new
                            "/user/token" ,
                            "/api/github/**"// endpoints
                    ).permitAll()
                    .anyRequest().authenticated()
            )
//            .formLogin(form -> form
//                    .loginPage("/login")
//                    .loginProcessingUrl("/login")
////                    .defaultSuccessUrl("http://localhost:8888/", true)
//                    .defaultSuccessUrl("/login?success=true", false)
//                    .failureUrl("/login?error=true")
//            )
            .formLogin(form -> form
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .defaultSuccessUrl("http://localhost:8888", true)  // Change this
                    .failureUrl("/login?error=true")
            )
            .oauth2Login(oauth2 -> oauth2
                    .loginPage("/login")
                    .defaultSuccessUrl("http://localhost:8888", true)  // And this
                    .userInfoEndpoint(userInfo -> userInfo
                            .userService(oauth2UserService()))
                    .failureHandler((request, response, exception) -> {
                        log.error("OAuth2 authentication failed: ", exception);
                        response.sendRedirect("/login?error=oauth2");
                    })
            )
//            .oauth2Login(oauth2 -> oauth2
//                    .loginPage("/login")
////                    .defaultSuccessUrl("http://localhost:8888/", true)
//                    .defaultSuccessUrl("/login?success=true", false)
//                    .userInfoEndpoint(userInfo -> userInfo
//                            .userService(oauth2UserService()))
//                    .failureHandler((request, response, exception) -> {
//                        log.error("OAuth2 authentication failed: ", exception);
//                        response.sendRedirect("/login?error=oauth2");
//                    })
//            )
            .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(Customizer.withDefaults())
            )
            .logout(logout -> logout
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("http://localhost:8888")
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
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
                if ("facebook".equals(userRequest.getClientRegistration().getRegistrationId())) {
                    try {
                        String accessToken = userRequest.getAccessToken().getTokenValue();
                        String appSecret = userRequest.getClientRegistration().getClientSecret();

                        // Generate appsecret_proof
                        String appsecretProof = generateAppSecretProof(accessToken, appSecret);

                        // Build Facebook Graph API URL with appsecret_proof
                        String graphURL = userRequest.getClientRegistration().getProviderDetails()
                                .getUserInfoEndpoint().getUri();
                        graphURL = String.format("%s?fields=id,name,email,picture&access_token=%s&appsecret_proof=%s",
                                graphURL, accessToken, appsecretProof);

                        RestTemplate restTemplate = new RestTemplate();
                        HttpHeaders headers = new HttpHeaders();
                        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

                        HttpEntity<String> entity = new HttpEntity<>("", headers);
                        ResponseEntity<Map> response = restTemplate.exchange(graphURL, HttpMethod.GET, entity, Map.class);

                        Map<String, Object> attributes = response.getBody();
                        return new DefaultOAuth2User(
                                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                                attributes,
                                "id"
                        );
                    } catch (Exception ex) {
                        log.error("Error fetching Facebook user info: ", ex);
                        throw new OAuth2AuthenticationException(
                                new OAuth2Error("user_info_error"),
                                "Error fetching user info from Facebook",
                                ex
                        );
                    }
                }
                return super.loadUser(userRequest);
            }
        };

        return delegate;
    }

    private String generateAppSecretProof(String accessToken, String appSecret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(appSecret.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] bytes = mac.doFinal(accessToken.getBytes());
            return bytesToHex(bytes);
        } catch (Exception e) {
            throw new RuntimeException("Error generating appsecret_proof", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    private OAuth2User processFacebookUser(OAuth2User oauth2User, String email) {
        User userEntity = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUuid(UUID.randomUUID().toString());
                    newUser.setEmail(email);
                    newUser.setUsername(email);
                    newUser.setEmailVerified(true);
                    newUser.setIsEnabled(true);
                    return userRepository.save(newUser);
                });

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());
        attributes.put("userUuid", userEntity.getUuid());

        return new DefaultOAuth2User(authorities, attributes, "id");
    }

    private OAuth2User processGithubUser(OAuth2User oauth2User) {
        String login = oauth2User.getAttribute("login");
        String email = login + "@github.com";

        User userEntity = userRepository.findByUsername(login)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUuid(UUID.randomUUID().toString());
                    newUser.setUsername(login);
                    newUser.setEmail(email);
                    newUser.setEmailVerified(true);
                    newUser.setIsEnabled(true);
                    return userRepository.save(newUser);
                });

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());
        attributes.put("userUuid", userEntity.getUuid());

        return new DefaultOAuth2User(authorities, attributes, "login");
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
                    // Get registration ID from OAuth2AuthenticationToken
                    if (authentication instanceof OAuth2AuthenticationToken oauth2Authentication) {
                        String registrationId = oauth2Authentication.getAuthorizedClientRegistrationId();
                        switch (registrationId) {
                            case "github" -> addGithubUserClaims(context, oauth2User);
                            case "facebook" -> addFacebookUserClaims(context, oauth2User);
                        }
                    }
                }
            }

            if (context.getTokenType().getValue().equals("access_token")) {
                addStandardClaims(context, authentication);

                if (principal instanceof CustomUserDetails customUserDetails) {
                    addCustomUserClaims(context, customUserDetails);
                } else if (principal instanceof DefaultOidcUser oidcUser) {
                    addGoogleUserClaims(context, oidcUser);
                } else if (principal instanceof DefaultOAuth2User oauth2User) {
                    // Get registration ID from OAuth2AuthenticationToken
                    if (authentication instanceof OAuth2AuthenticationToken oauth2Authentication) {
                        String registrationId = oauth2Authentication.getAuthorizedClientRegistrationId();
                        switch (registrationId) {
                            case "github" -> addGithubUserClaims(context, oauth2User);
                            case "facebook" -> addFacebookUserClaims(context, oauth2User);
                        }
                    }
                }
            }
        };
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
                } else if (principal instanceof DefaultOAuth2User oidcUser) {
                    addGithubUserClaims(context, oauth2User);
                } else if (principal instanceof DefaultOAuth2User oAuth2User) {
                    addFacebookUserClaims(context, oAuth2User);
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
private void addFacebookUserClaims(JwtEncodingContext context, DefaultOAuth2User user) {
    String email = user.getAttribute("email");
    log.debug("Processing Facebook claims for email: {}", email);

    userRepository.findByEmail(email)
            .ifPresentOrElse(
                    userEntity -> {
                        context.getClaims()
                                .claim("userUuid", userEntity.getUuid())
                                .claim("username", userEntity.getUsername())
                                .claim("email", userEntity.getEmail());
                        log.debug("Added claims for existing user: {}", userEntity.getEmail());
                    },
                    () -> {
                        context.getClaims()
                                .claim("email", email)
                                .claim("name", user.getAttribute("name"));
                        log.debug("Added claims for new Facebook user: {}", email);
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

}


