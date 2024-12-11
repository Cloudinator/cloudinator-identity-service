package istad.co.identity.security;

import istad.co.identity.domain.User;
import istad.co.identity.features.user.UserRepository;
import istad.co.identity.security.custom.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsernameAndIsEnabledTrue(username)
                .orElseThrow(() -> new UsernameNotFoundException("User with email " + username + " not found"));

        log.info("loadUserByUsername: {}", user);

        CustomUserDetails customUserDetails = new CustomUserDetails();
        customUserDetails.setUser(user);

        System.out.println(customUserDetails.getUsername());

        return customUserDetails;
    }
}