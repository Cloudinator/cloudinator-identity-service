package istad.co.identity.features.auth.theamleaf;

import istad.co.identity.features.auth.AuthService;
import istad.co.identity.features.auth.dto.LoginRequest;
import istad.co.identity.features.user.dto.UserResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

@Controller
public class LoginController {

    private final AuthService authService;

    public LoginController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String handleLogin(@RequestParam String username,
                              @RequestParam String password,
                              Model model) {
        try {
            LoginRequest loginRequest = new LoginRequest(username, password);
            UserResponse response = authService.login(loginRequest);

            // Log successful login
            System.out.println("Successful login for user: " + username);

            return "redirect:/dashboard";
        } catch (ResponseStatusException e) {
            // Log failed login attempt
            System.out.println("Failed login attempt for user: " + username +
                    " - Error: " + e.getReason());

            model.addAttribute("error", e.getReason());
            model.addAttribute("username", username);
            return "login";
        }
    }
}