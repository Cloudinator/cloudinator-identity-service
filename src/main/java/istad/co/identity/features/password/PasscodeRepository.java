package istad.co.identity.features.password;

import istad.co.identity.domain.Passcode;
import istad.co.identity.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface PasscodeRepository extends JpaRepository<Passcode,Long> {

    Optional<Passcode> findByToken(String token);

    Passcode findByUser(User user);

    @Transactional
    @Modifying
    @Query("DELETE FROM Passcode e where e.user=:user")
    void deleteByUser(@Param("user") User user);
}