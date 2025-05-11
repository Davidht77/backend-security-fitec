package com.dev.security.Auth.application;

import com.dev.security.Auth.domain.AuthenticationService;
import com.dev.security.Auth.dto.AuthResponse;
import com.dev.security.Auth.dto.LoginRequest;
import com.dev.security.Auth.dto.RegisterClientRequest;
import com.dev.security.Auth.dto.RegisterEmployeeRequest;
import com.dev.security.Invitation.dto.InvitationTokenResponse;
import com.dev.security.Invitation.dto.InviteEmployeeRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationService authService;


    @PostMapping("/register/client")
    Mono<Void> registrarse1(@RequestBody RegisterClientRequest registerRequest){
        return authService.registerUser(registerRequest);
    }

    @PostMapping("/admin/invite-employee")
    public Mono<ResponseEntity<InvitationTokenResponse>> inviteEmployee(@Valid @RequestBody InviteEmployeeRequest request) {
        return authService.initiateEmployeeInvitation(request)
                .map(ResponseEntity::ok) // Si tiene éxito, devuelve 200 OK con el cuerpo
                .onErrorResume(e -> {
                    // Loguear el error e.getMessage()
                    System.err.println("Error initiating employee invitation: " + e.getMessage());
                    // Puedes devolver un cuerpo de error más específico si quieres
                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(null));
                });
    }

    @PostMapping("/register/employee")
    Mono<Void> registrarse2(@RequestBody RegisterEmployeeRequest registerRequest){
        return authService.registerEmployee(registerRequest);
    }

    @PostMapping("/login")
    Mono<ResponseEntity<AuthResponse>> logearse(@RequestBody LoginRequest loginRequest){
        return authService.login(loginRequest) // Obtiene Mono<AuthResponse>
                .map(ResponseEntity::ok);
    }
}
