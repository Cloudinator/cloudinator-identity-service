package istad.co.identity.domain;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "groups")
@Getter
@Setter
@NoArgsConstructor
public class Group {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String uuid;
    private String groupName;
    private String path;
    private Integer projectId;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

}