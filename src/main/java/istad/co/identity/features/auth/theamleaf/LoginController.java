package istad.co.identity.features.auth.theamleaf;

import istad.co.identity.features.auth.AuthService;
import istad.co.identity.features.auth.dto.LoginRequest;
import istad.co.identity.features.user.UserService;
import istad.co.identity.features.user.dto.UserResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

@Controller
@Slf4j
@RequiredArgsConstructor
public class LoginController {
    private final AuthService authService;
    private final UserService userService;
    @GetMapping("/login")
    public String showLoginPage(@RequestParam(required = false) String error,
                                @RequestParam(required = false) String verified,
                                Model model) {
        if (error != null) {
            model.addAttribute("error", "Invalid credentials");
        }
        if ("true".equals(verified)) {
            model.addAttribute("successMessage", "Email verified successfully! You can now log in.");
        }
        return "login";
    }
    @PostMapping("/clear-oauth-message")
    @ResponseBody
    public void clearOAuthMessage(HttpSession session) {
        session.removeAttribute("oauthMessage");
    }

    @PostMapping("/clear-oauth-error")
    @ResponseBody
    public void clearOAuthError(HttpSession session) {
        session.removeAttribute("oauthError");
    }
//    @GetMapping("/reset-password")
//    public String showResetPasswordForm() {
//        return "reset-password";
//    }
//
//    @PostMapping("/reset-password")
//    public String handleResetPassword(@RequestParam String email, Model model) {
//        // TODO: Implement actual password reset logic here
//        // For now, we'll just show a success message
//        model.addAttribute("message", "If an account exists for " + email + ", we have sent a password reset link.");
//        return "login";
//    }
    @PostMapping("/login")
    public String handleLogin(@RequestParam String username,
                              @RequestParam String password,
                              Model model,
                              HttpSession session) {
        try {
            log.info("Attempting login for user: {}", username);
            LoginRequest loginRequest = new LoginRequest(username, password);

            // First check if user exists
            try {
                UserResponse user = userService.findByUsername(username);

                // Check email verification
                if (!user.emailVerified()) {
                    log.warn("Login attempt for unverified email: {}", username);
                    model.addAttribute("error", "Please verify your email before logging in");
                    model.addAttribute("verificationNeeded", true);
                    model.addAttribute("username", username);
                    return "login";
                }

                // Attempt login
                UserResponse response = authService.login(loginRequest);
                if (response != null) {
                    log.info("Login successful for user: {}", username);
                    session.setAttribute("user", response);
                    return "redirect:/dashboard";
                }
            } catch (ResponseStatusException e) {
                if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                    log.warn("Login attempt with non-existent username: {}", username);
                    model.addAttribute("error", "Username not found");
                    model.addAttribute("username", username);
                    return "login";
                }
                throw e;
            }

            model.addAttribute("error", "Invalid credentials");
            return "login";

        } catch (ResponseStatusException e) {
            String errorMessage = switch (e.getStatusCode().value()) {
                case 401 -> {
                    log.warn("Invalid password attempt for user: {}", username);
                    yield "Invalid password";
                }
                case 403 -> {
                    log.warn("Login attempt for unverified account: {}", username);
                    model.addAttribute("verificationNeeded", true);
                    yield "Your account is not verified. Please check your email";
                }
                case 423 -> {
                    log.warn("Login attempt for locked account: {}", username);
                    yield "Account is locked. Please contact support";
                }
                default -> {
                    log.error("Unexpected error during login for user {}: {}", username, e.getMessage());
                    yield "An error occurred. Please try again";
                }
            };

            model.addAttribute("error", errorMessage);
            model.addAttribute("username", username);
            return "login";
        }
    }
}