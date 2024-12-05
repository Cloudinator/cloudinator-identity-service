package istad.co.identity.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "verify")
public class Verify {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String uuid;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, columnDefinition = "BOOLEAN DEFAULT FALSE")
    private Boolean isVerified;

    @Column
    private LocalDateTime verifiedDate;

    @Column(nullable = false, length = 64)
    private String otpCode;

    @Column(nullable = false)
    private LocalDateTime otpExpiration;

    @Column(nullable = false, columnDefinition = "INTEGER DEFAULT 0")
    private Integer otpAttempts;

}