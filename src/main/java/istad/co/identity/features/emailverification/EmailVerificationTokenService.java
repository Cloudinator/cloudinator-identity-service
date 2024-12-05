package istad.co.identity.features.emailverification;

import istad.co.identity.domain.EmailVerificationToken;
import istad.co.identity.domain.User;
import istad.co.identity.features.emailverification.dto.EmailVerifyRequest;

public interface EmailVerificationTokenService {

    void verify(EmailVerifyRequest emailVerifyRequest);

    boolean isUsersToken(EmailVerificationToken token, User user);

    boolean isTokenInDb(EmailVerificationToken token, String tokenToVerify);

    void generate(User user);

    boolean isExpired(EmailVerificationToken token);

    void resend(String username);

}
