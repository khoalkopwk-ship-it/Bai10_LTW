package vn.iotstar.service;

import vn.iotstar.dto.LoginUserDTO;
import vn.iotstar.dto.RegisterUserDTO;
import vn.iotstar.Entity.User;
import vn.iotstar.repository.UserRepository;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public User signup(RegisterUserDTO input) {

        User user = new User();

        user.setFullName(input.getFullName());
        user.setEmail(input.getEmail());

        user.setPassword(
                passwordEncoder.encode(input.getPassword())
        );

        return userRepository.save(user);
    }

    public User authenticate(LoginUserDTO input) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );

        return userRepository.findByEmail(input.getEmail())
                .orElseThrow();
    }
}
