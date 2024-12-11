package istad.co.identity.security.domain;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@Entity
@Table(name = "authorization_consents")
@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
@NoArgsConstructor
public class AuthorizationConsent {
    @Id
    private String registeredClientId;

    @Id
    private String principalName;

    @Column(columnDefinition = "TEXT")
    private String authorities;

    @Getter
    @Setter
    @EqualsAndHashCode
    @NoArgsConstructor
    public static class AuthorizationConsentId implements Serializable {
        private String registeredClientId;
        private String principalName;
    }

}