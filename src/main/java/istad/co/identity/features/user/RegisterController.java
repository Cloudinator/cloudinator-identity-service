package istad.co.identity.features.user;

import istad.co.identity.features.user.dto.UserCreateRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/register")
@RequiredArgsConstructor
@Slf4j
public class RegisterController {
    private final UserService userService;
    private final GitLabServiceFein gitLabServiceFein;

    @GetMapping
    public String showRegisterForm(Model model) {
        if (!model.containsAttribute("userRequest")) {
            UserCreateRequest userRequest = UserCreateRequest.builder()
                    .username("")
                    .password("")
                    .confirmedPassword("")
                    .email("")
                    .acceptTerms("")
                    .build();
            model.addAttribute("userRequest", userRequest);
        }
        return "register";
    }

    @PostMapping
    public ResponseEntity<?> registerUser(@Valid @ModelAttribute("userRequest") UserCreateRequest userCreateRequest,
                                          BindingResult bindingResult) {
        log.info("Processing registration for user: {}", userCreateRequest.username());

        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            bindingResult.getFieldErrors().forEach(error ->
                    errors.put(error.getField(), error.getDefaultMessage()));
            return ResponseEntity.badRequest().body(errors);
        }

        try {
            userService.createNewUser(userCreateRequest);
            return ResponseEntity.ok().body(Map.of("message", "Registration successful!"));
        } catch (ResponseStatusException e) {
            log.error("Registration failed for user {}: {}",
                    userCreateRequest.username(), e.getMessage());
            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(Map.of("message", e.getReason()));
        } catch (Exception e) {
            log.error("Unexpected error during registration", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "An unexpected error occurred"));
        }
    }
}