package com.advanced.individualsapi.configuration;

import com.advanced.individualsapi.controller.AuthController;
import com.advanced.individualsapi.controller.GlobalExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.web.reactive.server.WebTestClient;

@Configuration
public class WebTestClientConfiguration {

    @Bean
    public WebTestClient getAuthControllerWebClient(AuthController authController) {
        return WebTestClient.bindToController(authController)
                .controllerAdvice(new GlobalExceptionHandler())
                .build();
    }

}
