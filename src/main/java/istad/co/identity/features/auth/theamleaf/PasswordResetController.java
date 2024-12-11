package istad.co.identity.features.auth.theamleaf;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class PasswordResetController {

    @GetMapping("/forgot-password")
    public String showForgotPasswordPage() {
        return "password/forgot-password";  // This will render forgot-password.html
    }

    @GetMapping("/verify-code")
    public String showVerifyCodePage(@RequestParam String username, Model model) {
        model.addAttribute("username", username);
        return "password/verify-code";  // This will render verify-code.html
    }

    @GetMapping("/reset-password")
    public String showResetPasswordPage(
            @RequestParam String username,
            @RequestParam String token,
            Model model
    ) {
        model.addAttribute("username", username);
        model.addAttribute("token", token);
        return "password/reset-password";  // This will render reset-password.html
    }
}