package istad.co.identity.features.auth.theamleaf;

import istad.co.identity.features.emailverification.EmailVerificationTokenService;
import istad.co.identity.features.emailverification.dto.EmailVerifyRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/verify-email")
@RequiredArgsConstructor
public class EmailVerificationViewController {
    private final EmailVerificationTokenService emailVerificationTokenService;

    @GetMapping
    public String showVerificationForm(@RequestParam(required = false) String username, Model model) {
        EmailVerifyRequest emailVerifyRequest = EmailVerifyRequest.builder()
                .username(username)
                .token("")
                .build();
        model.addAttribute("emailVerifyRequest", emailVerifyRequest);
        return "verify-email";
    }

    @PostMapping
    public String verifyEmail(@Valid @ModelAttribute EmailVerifyRequest emailVerifyRequest,
                              BindingResult bindingResult,
                              RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            return "verify-email";
        }

        try {
            emailVerificationTokenService.verify(emailVerifyRequest);
            redirectAttributes.addFlashAttribute("success", "Email verified successfully. You can now login.");
            return "redirect:/login";
        } catch (ResponseStatusException e) {
            bindingResult.rejectValue("token", "error.emailVerifyRequest", e.getReason());
            return "verify-email";
        } catch (Exception e) {
            bindingResult.rejectValue("token", "error.emailVerifyRequest", "An error occurred during verification.");
            return "verify-email";
        }
    }
}