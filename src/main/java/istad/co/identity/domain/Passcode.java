package istad.co.identity.domain;

import istad.co.identity.config.jpa.Auditable;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@ToString
@Entity
@Table(name = "passcodes")
public class Passcode  extends Auditable<String> {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    @Column(nullable = false, columnDefinition = "VARCHAR(256)")
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiryDateTime;

    private Boolean isValidated;

    @OneToOne
    private User user;

}