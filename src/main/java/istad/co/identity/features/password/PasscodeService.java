package istad.co.identity.features.password;

import istad.co.identity.domain.Passcode;
import istad.co.identity.domain.User;
import istad.co.identity.features.password.dto.PasscodeVerifyRequest;
import istad.co.identity.features.password.dto.PasscodeVerifyResendRequest;

/**
 * Passcode interface which contains methods to manage passcode when forgot password
 *
 * @author Ing Muyleang
 * @since 1.0 (2024)
 */
public interface PasscodeService {

    /**
     * verify passcode(OTG)
     *
     * @param passcodeVerifyRequest is the requirement information for verified passcode
     * @author Ing Muyleang
     * @since 1.0 (2024)
     */
    void verify(PasscodeVerifyRequest passcodeVerifyRequest);

    /**
     * resend passcode
     *
     * @param passcodeVerifyResendRequest is the requirement information for resent the passcode
     * @author Ing Muyleang
     * @since 1.0 (2024)
     */

    void resend(PasscodeVerifyResendRequest passcodeVerifyResendRequest);

    /**
     * generate and send OTG passcode to user
     *
     * @param user is the object of user to send passcode
     * @author Ing Muyleang
     * @since 1.0 (2024)
     */
    void generate(User user);

    /**
     * check the token belong to user or not
     *
     * @param token is the token to validate with user
     * @param user  is the user that need to validate with token
     * @return {@link Boolean}
     * @author Ing Muyleang
     * @since 1.0 (2024)
     */

    boolean isUsersToken(Passcode token, User user);

    /**
     * check the token has expired or not yet
     *
     * @param token is the token to check
     * @return {@link Boolean}
     * @author Ing Muyleang
     * @since 1.0 (2024)
     */
    boolean isExpired(Passcode token);
}