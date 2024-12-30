package istad.co.identity.features.user;

import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserPasswordResetResponse;
import istad.co.identity.features.user.dto.UserResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    private final GitLabServiceFein gitLabServiceFein;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    void createNew(@Valid @RequestBody UserCreateRequest userCreateRequest) {

        gitLabServiceFein.createUser(userCreateRequest.username() , userCreateRequest.email(), userCreateRequest.password());

        userService.createNewUser(userCreateRequest);
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getMe(Authentication authentication) {
        return ResponseEntity.ok(userService.getAuthenticatedUser(authentication));
    }



    //    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @PutMapping("/{username}/reset-password")
    UserPasswordResetResponse resetPassword(@PathVariable String username) {
        return userService.resetPassword(username);
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PutMapping("/{username}/disable")
    void disable(@PathVariable String username) {
        userService.disable(username);
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PutMapping("/{username}/enable")
    void enable(@PathVariable String username) {
        userService.enable(username);
    }


    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @GetMapping
    Page<UserResponse> findList(@RequestParam(required = false, defaultValue = "0") int pageNumber,
                                @RequestParam(required = false, defaultValue = "25") int pageSize) {
        return userService.findList(pageNumber, pageSize);
    }

    //    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/{username}")
    UserResponse findByUsername(@PathVariable String username) {
        return userService.findByUsername(username);
    }


}