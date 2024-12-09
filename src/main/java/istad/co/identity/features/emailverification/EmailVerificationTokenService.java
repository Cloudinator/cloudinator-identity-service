package istad.co.identity.features.emailverification;

import istad.co.identity.domain.User;
import istad.co.identity.domain.VerificationToken;
import istad.co.identity.features.emailverification.dto.EmailVerifyRequest;

public interface EmailVerificationTokenService {

    void verify(EmailVerifyRequest emailVerifyRequest);

    boolean isUsersToken(VerificationToken token, User user);

    void generate(User user);

    boolean isExpired(VerificationToken token);

    void resend(String username);

}