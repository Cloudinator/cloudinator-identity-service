package istad.co.identity.features.auth;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
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

//    @GetMapping("/test-github")
//    public String testGithub(@RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient client) {
//        return "Github connection test successful! Token: " + client.getAccessToken().getTokenValue();
//    }

}
