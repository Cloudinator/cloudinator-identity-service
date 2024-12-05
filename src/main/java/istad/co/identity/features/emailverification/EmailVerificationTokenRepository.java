package istad.co.identity.features.emailverification;

import istad.co.identity.domain.EmailVerificationToken;
import istad.co.identity.domain.User;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends CrudRepository<EmailVerificationToken, Long> {

    Optional<EmailVerificationToken> getByToken(String token);

    @Transactional
    @Modifying
    @Query("DELETE FROM EmailVerificationToken e where e.user=:user")
    void deleteByUser(@Param("user") User user);
}
