package istad.co.identity.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "personal_tokens")
@Getter
@Setter
@NoArgsConstructor
public class PersonalToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String uuid;
    private String token;
    private Integer idUser;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

}
