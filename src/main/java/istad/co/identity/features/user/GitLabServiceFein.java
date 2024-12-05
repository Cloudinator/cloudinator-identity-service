package istad.co.identity.features.user;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "project-service")
public interface GitLabServiceFein {

    @PostMapping("/api/v1/gitlab/create-user")
    public void createUser(@RequestParam String username, @RequestParam String password, @RequestParam String email);

}
