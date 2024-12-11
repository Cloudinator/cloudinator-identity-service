package istad.co.identity.features.authority;

import istad.co.identity.domain.Authority;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthorityRepository extends CrudRepository<Authority, Integer> {

    @Query("select e from #{#entityName} e where e.name='USER'")
    Authority AUTH_USER();


    @Query("select e from #{#entityName} e where e.name='ADMIN'")
    Authority AUTH_ADMIN();

    Optional<Authority> findByName(String name);

}
