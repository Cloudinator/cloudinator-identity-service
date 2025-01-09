package istad.co.identity.features.user;

import istad.co.identity.domain.PersonalToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PersonalRepository extends JpaRepository<PersonalToken,Long> {

    Optional<PersonalToken> findByUser_Username (String username);

}
