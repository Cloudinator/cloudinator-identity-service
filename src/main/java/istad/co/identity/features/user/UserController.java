package istad.co.identity.features.user;

import istad.co.identity.features.user.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
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

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/count")
    public ResponseEntity<Integer> countUsers() {
        return ResponseEntity.ok(userService.countUsers());
    }



    //    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @PutMapping("/{username}/reset-password")
    UserPasswordResetResponse resetPassword(@PathVariable String username) {
        return userService.resetPassword(username);
    }

    @PreAuthorize("isAuthenticated()")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PostMapping("/disable/{username}")
    public ResponseEntity<String> disable(@PathVariable String username) {

        log.info("Disabling user: {}", username);

        userService.disable(username);

        return ResponseEntity.ok("User disabled successfully");
    }

    @PreAuthorize("isAuthenticated()")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PostMapping("/enable/{username}")
    public ResponseEntity<String> enable(@PathVariable String username) {
        userService.enable(username);

        return ResponseEntity.ok("User enabled successfully");
    }


//    @PreAuthorize("hasAnyAuthority('ADMIN')")
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

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/get-all-users-details")
    public ResponseEntity<List<UserProfileResponse>> getAllUsersDetails() {
        return ResponseEntity.ok(userService.getAllUserProfiles());
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/test-method/{username}")
    public ResponseEntity<String> testMethod(@PathVariable String username) {
        userService.testMethod(username);
        return ResponseEntity.ok("Test method executed successfully");
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/{username}")
    public ResponseEntity<String> deleteUser(@PathVariable String username) {
        userService.deleteByUsername(username);
        return ResponseEntity.ok("User deleted successfully");
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/{username}/update-profile")
    public ResponseEntity<UserProfileResponse> updateUserProfile(
            @PathVariable String username,
            @Valid @RequestBody UserProfileUpdateRequest updateRequest,
            Authentication authentication) {

        // Log the update request
        log.info("Updating profile for user: {}", authentication.getName());

        // Ensure the authenticated user can only update their own profile
        if (!authentication.getName().equals(username)) {
            throw new AccessDeniedException("You are not authorized to update this profile.");
        }

        // Call the service to update the user profile
        UserProfileResponse updatedProfile = userService.updateUserProfile(authentication.getName(), updateRequest);

        // Return the updated profile in the response
        return ResponseEntity.ok(updatedProfile);
    }



}