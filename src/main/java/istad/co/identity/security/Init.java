package istad.co.identity.security;

import istad.co.identity.domain.Administrator;
import istad.co.identity.domain.Authority;
import istad.co.identity.domain.User;
import istad.co.identity.domain.UserAuthority;
import istad.co.identity.features.administrator.AdministratorRepository;
import istad.co.identity.features.authority.AuthorityRepository;
import istad.co.identity.features.user.UserRepository;
import istad.co.identity.security.repository.JpaRegisteredClientRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDate;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class Init {

    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorityRepository authorityRepository;
    private final UserRepository userRepository;
    private final AdministratorRepository administratorRepository;

    @PostConstruct
    void initUserDetails() {

        if (userRepository.count() < 1) {

            // Authority initialization
            Authority user = new Authority();
            user.setName("USER");
            authorityRepository.save(user);

            Authority system = new Authority();
            system.setName("SYSTEM");
            authorityRepository.save(system);

            Authority admin = new Authority();
            admin.setName("ADMIN");
            authorityRepository.save(admin);

            Authority editor = new Authority();
            editor.setName("EDITOR");
            authorityRepository.save(editor);


            // User initialization
            User adminUser = new User();
            adminUser.setUuid(UUID.randomUUID().toString());
            adminUser.setUsername("admin");
            adminUser.setEmail("admin@devops.com");
            adminUser.setPassword(passwordEncoder.encode("Qwerty@2024"));

            adminUser.setProfileImage("avatar.png");

            adminUser.setEmailVerified(true);
            adminUser.setIsEnabled(true);
            adminUser.setCredentialsNonExpired(true);
            adminUser.setAccountNonLocked(true);
            adminUser.setAccountNonExpired(true);

            // start setup user authorities for admin
            UserAuthority defaultUserAuthority = new UserAuthority(); // default
            defaultUserAuthority.setUser(adminUser);
            defaultUserAuthority.setAuthority(user);

            UserAuthority adminAuthority = new UserAuthority(); // admin
            adminAuthority.setUser(adminUser);
            adminAuthority.setAuthority(admin);

//            UserAuthority bizAuthority = new UserAuthority();
//            bizAuthority.setUser(adminUser);
//            bizAuthority.setAuthority(businessOwner);

            adminUser.setUserAuthorities(Set.of(defaultUserAuthority, adminAuthority));
            // end setup user authorities for admin

            Administrator administrator = new Administrator();
            administrator.setUser(adminUser);
            administratorRepository.save(administrator);
        }

    }

    @PostConstruct
    void initOAuth2() {

        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofDays(100))
                .build();

        ClientSettings clientSettings = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(false)
                .build();

        var web = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("devops")
                .clientSecret(passwordEncoder.encode("Qwerty@2024")) // store in secret manager
                .scopes(scopes -> {
                    scopes.add(OidcScopes.OPENID);
                    scopes.add(OidcScopes.PROFILE);
                    scopes.add(OidcScopes.EMAIL);
                })
                .redirectUris(uris -> {
                    uris.add("http://34.87.156.153:8081/login/oauth2/code/devops");
                    uris.add("http://localhost:8081/login/oauth2/code/devops");
                    uris.add("https://cloudinator-ui.cloudinator.cloud/login/oauth2/code/devops");
                    uris.add("http://34.87.156.153:8087/login/oauth2/code/devops");
                })
                .postLogoutRedirectUris(uris -> {
                    uris.add("https://cloudinator-ui.cloudinator.cloud");
                    uris.add("http://34.87.156.153:8081");
                    uris.add("http://localhost:8081");
                })
                .clientAuthenticationMethods(method -> {
                    method.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                }) //TODO: grant_type:client_credentials, client_id & client_secret, redirect_uri
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId("devops");

        if (registeredClient == null) {
            jpaRegisteredClientRepository.save(web);
        }

    }

}