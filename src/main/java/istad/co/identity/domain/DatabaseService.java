package istad.co.identity.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "database_service")
public class DatabaseService {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String uuid;

    @Column(nullable = false, length = 64)
    private String name;

    @Column(nullable = false, length = 64)
    private String password;

    @Column(nullable = false)
    private int port;

    @Column(nullable = false, length = 64)
    private String dbName;

    @Column(nullable = false, length = 64)
    private String dbType;

    @Column(nullable = false)
    String dbVersion;

    @Column(nullable = false)
    private String type;

    @Column(nullable = false, length = 64)
    private String subdomain;

    @ManyToOne
    @JoinColumn(name = "workspace_id", nullable = false)
    private WorkSpace workspace;

}