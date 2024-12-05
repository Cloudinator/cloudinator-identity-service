package istad.co.identity.features.user;


import istad.co.identity.domain.User;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserPasswordResetResponse;
import istad.co.identity.features.user.dto.UserResponse;
import org.springframework.data.domain.Page;

public interface UserService {

    void createNewUser(UserCreateRequest userCreateRequest);

    UserPasswordResetResponse resetPassword(String username);

    void enable(String username);

    void disable(String username);

    Page<UserResponse> findList(int pageNumber, int pageSize);

    UserResponse findByUsername(String username);

    void checkForPasswords(String password, String confirmPassword);

    void checkTermsAndConditions(String value);

    void existsByUsername(String username);

    void existsByEmail(String email);

    void verifyEmail(User user);

    void checkForOldPassword(String username, String oldPassword);

}
