package istad.co.identity.domain;

import istad.co.identity.config.jpa.Auditable;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "users")
@Builder
@AllArgsConstructor
public class User extends Auditable<String> {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String uuid;

    @Column(nullable = false, unique = true, length = 64)
    private String username;

    @Column(nullable = false, unique = true, length = 256)
    private String email;

    @Column(nullable = true, length = 256)
    private String password;

    @Column(unique = true, length = 256)
    private String facebookId;

    @Column(unique = true, length = 256)
    private String googleId;

    @Column(unique = true, length = 256)
    private String xId;

    @Column(unique = true, length = 256)
    private String telegramId;

    @Column(unique = true, length = 256)
    private String appleId;

    @Column(name = "profile_image", columnDefinition = "TEXT")  // Changed to TEXT type
    private String profileImage;


    @Column(length = 256)
    private String ipAddress;

    @Column(columnDefinition = "BOOLEAN DEFAULT TRUE")
    private Boolean accountNonExpired;

    @Column(unique = true)
    private String phoneNumber;

    @Column(columnDefinition = "BOOLEAN DEFAULT TRUE")
    private Boolean accountNonLocked;

    @Column(columnDefinition = "BOOLEAN DEFAULT TRUE")
    private Boolean credentialsNonExpired;

    @Column(columnDefinition = "BOOLEAN DEFAULT FALSE")
    private Boolean isEnabled;

    @Column(columnDefinition = "BOOLEAN DEFAULT FALSE")
    private Boolean emailVerified;

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER, cascade = CascadeType.REMOVE)
    private Set<UserAuthority> userAuthorities;

}