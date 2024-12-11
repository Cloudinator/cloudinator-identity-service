package istad.co.identity.security.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "clients")
public class Client {

    @Id
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    @Column(columnDefinition = "TEXT")
    private String clientAuthenticationMethods;
    @Column(columnDefinition = "TEXT")
    private String authorizationGrantTypes;
    @Column(columnDefinition = "TEXT")
    private String redirectUris;
    @Column(columnDefinition = "TEXT")
    private String postLogoutRedirectUris;
    @Column(columnDefinition = "TEXT")
    private String scopes;
    @Column(columnDefinition = "TEXT")
    private String clientSettings;
    @Column(columnDefinition = "TEXT")
    private String tokenSettings;

}