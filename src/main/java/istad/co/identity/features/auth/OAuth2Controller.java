package istad.co.identity.features.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/oauth2")
public class OAuth2Controller {

    @GetMapping("/login")
    String viewLogin() {
        return "oauth2/login";
    }



}
