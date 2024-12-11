package istad.co.identity.features.user;

import istad.co.identity.features.user.dto.UserCreateRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

@Controller
@RequestMapping("/register")
@RequiredArgsConstructor
public class RegisterController {
    private final UserService userService;
    private final GitLabServiceFein gitLabServiceFein;

    @GetMapping
    public String showRegisterForm(Model model) {
        UserCreateRequest userRequest = UserCreateRequest.builder()
                .username("")
                .password("")
                .confirmedPassword("")
                .email("")
                .acceptTerms("")
                .build();
        model.addAttribute("userRequest", userRequest);
        return "register";
    }

    @PostMapping
    public String registerUser(@Valid @ModelAttribute("userRequest") UserCreateRequest userCreateRequest,
                               BindingResult bindingResult,
                               RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            return "register";
        }

        try {
            userService.createNewUser(userCreateRequest);
//            gitLabServiceFein.createUser(userCreateRequest.username() , userCreateRequest.email(), userCreateRequest.password());
            redirectAttributes.addFlashAttribute("success", "Registration successful! Please check your email to verify your account.");
            return "redirect:/verify-email?username=" + URLEncoder.encode(userCreateRequest.username(), StandardCharsets.UTF_8);
        } catch (ResponseStatusException e) {
            bindingResult.rejectValue("username", "error.userRequest", e.getReason());
            return "register";
        } catch (Exception e) {
            bindingResult.rejectValue("username", "error.userRequest", "An error occurred during registration.");
            return "register";
        }
    }
}