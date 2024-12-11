package istad.co.identity.domain;


import istad.co.identity.config.jpa.Auditable;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalTime;

@Getter
@Setter
@NoArgsConstructor
@ToString
@Entity
@Table(name = "email_verification_tokens")
public class VerificationToken extends Auditable<String> {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String token;

    @Column(nullable = false)
    private LocalTime expiration;

    @OneToOne
    private User user;

}