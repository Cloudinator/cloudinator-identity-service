package istad.co.identity.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "micro_service")
public class MicroService {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String uuid;

    @Column(nullable = false, length = 64)
    private String namespace;

    @Column(nullable = false, length = 64)
    private String git;

    @Column(nullable = false, length = 64)
    private String serviceName;

    @ManyToOne
    @JoinColumn(name = "env_id", nullable = false)
    private Environment env;

    @ManyToOne
    @JoinColumn(name = "sub_workspace_id", nullable = false)
    private SubWorkspace subWorkspace;

}