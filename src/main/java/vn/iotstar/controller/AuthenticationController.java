package vn.iotstar.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import vn.iotstar.Entity.User;
import vn.iotstar.dto.LoginResponse;
import vn.iotstar.dto.LoginUserDTO;
import vn.iotstar.dto.RegisterUserDTO;
import vn.iotstar.service.AuthenticationService;
import vn.iotstar.service.JWTService;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final JWTService jwtService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(
            JWTService jwtService,
            AuthenticationService authenticationService
    ) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> register(
            @jakarta.validation.Valid @RequestBody RegisterUserDTO registerUserDTO
    ) {

        User registeredUser =
                authenticationService.signup(registerUserDTO);

        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(
            @jakarta.validation.Valid @RequestBody LoginUserDTO loginUserDTO
    ) {

        User authenticatedUser =
                authenticationService.authenticate(loginUserDTO);

        String jwtToken =
                jwtService.generateToken(authenticatedUser);

        LoginResponse loginResponse =
                new LoginResponse(
                        jwtToken,
                        jwtService.getExpirationTime()
                );

        return ResponseEntity.ok(loginResponse);
    }
}
