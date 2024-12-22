package istad.co.identity.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "service_deploy")
public class ServiceDeploy {

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
    private String branch;

    @Column(nullable = false, length = 64)
    private String domainUuid;

}