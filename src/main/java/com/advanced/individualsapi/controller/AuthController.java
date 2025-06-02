package com.advanced.individualsapi.controller;

import com.advanced.individualsapi.dto.*;
import com.advanced.individualsapi.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/registration")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<AuthResponse> register(@Valid @RequestBody RegistrationRequest request) {
        return userService.register(request);
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public Mono<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return userService.login(request);
    }

    @PostMapping("/refresh-token")
    @ResponseStatus(HttpStatus.OK)
    public Mono<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return userService.refreshToken(request);
    }

    @GetMapping("/me")
    @ResponseStatus(HttpStatus.OK)
    public Mono<UserResponse> getUser(@RequestHeader("Authorization") String authorization) {
        return userService.getUser(authorization);
    }
}
