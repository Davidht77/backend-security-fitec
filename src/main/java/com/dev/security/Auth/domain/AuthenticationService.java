package com.dev.security.Auth.domain;

import com.dev.security.Auth.dto.*;
import com.dev.security.Config.JwtService;
import com.dev.security.Auth.dto.RegisterEmployeeRequest;
import com.dev.security.Invitation.dto.InvitationTokenResponse;
import com.dev.security.Invitation.dto.InviteEmployeeRequest;
import com.dev.security.Invitation.dto.ValidateInvitationDto;
import com.dev.security.Invitation.dto.ValidateInvitationResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class AuthenticationService {

    private final WebClient.Builder webClientBuilder;
    private final PasswordEncoder passwordEncoder;
    private final String clientServiceUrl;
    private final String employeeServiceUrl;
    private final JwtService jwtTokenProvider;
    private final String invitationServiceUrl; // Ya lo tenías con @Value


    public AuthenticationService(
            WebClient.Builder webClientBuilder,
            PasswordEncoder passwordEncoder,
            @Value("${app.services.client.base-url}") String clientServiceUrl,
            @Value("${app.services.employee.base-url}") String employeeServiceUrl,
            @Value("${app.services.invitation.base-url}") String invitationServiceUrl, // Inyecta la URL
            JwtService jwtTokenProvider) {
        this.webClientBuilder = webClientBuilder;
        this.passwordEncoder = passwordEncoder;
        this.clientServiceUrl = clientServiceUrl;
        this.employeeServiceUrl = employeeServiceUrl;
        this.invitationServiceUrl = invitationServiceUrl; // Asigna la URL
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // --- NUEVO METODO: INICIAR INVITACIÓN DE EMPLEADO ---
    public Mono<InvitationTokenResponse> initiateEmployeeInvitation(InviteEmployeeRequest inviteRequest) {
        // Llama al servicio de invitaciones (NestJS) para crear un token
        return webClientBuilder.baseUrl(invitationServiceUrl).build()
                .post()
                .uri("/invitations") // Endpoint en el servicio de NestJS para crear invitaciones
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(inviteRequest)
                .retrieve()
                .onStatus(
                        HttpStatusCode::isError,
                        response -> response.bodyToMono(String.class)
                                .defaultIfEmpty("[No error body provided from invitation service]")
                                .flatMap(errorBody -> {
                                    String errorMessage = "Invitation service error during creation: " + response.statusCode() + " - " + errorBody;
                                    return Mono.error(new RuntimeException(errorMessage));
                                })
                )
                .bodyToMono(InvitationTokenResponse.class)
                .doOnSuccess(response -> {
                    // Aquí podrías desencadenar el envío del email si este servicio es responsable
                    // o si el servicio de NestJS no lo hace.
                    System.out.println("Invitación creada para: " + response.getInvitedEmail() + ", Token: " + response.getToken());
                });
    }

    public Mono<Void> registerUser(RegisterClientRequest request) {
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // Determina a qué servicio llamar
            ClientDTO clientData = new ClientDTO(
                    request.getName(),
                    request.getLastName(),
                    request.getAge(),
                    request.getPhone(),
                    request.getEmail(),
                    hashedPassword, // Envía la contraseña ya hasheada
                    request.getPlanName()
            );

            // Llama al ClientService
            return webClientBuilder.baseUrl(clientServiceUrl).build()
                    .post()
                    .uri("/client") // Endpoint en ClientService para crear clientes
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(clientData) // El objeto a enviar como JSON
                    .retrieve() // Envía la solicitud y obtén la respuesta
                    .onStatus(
                            HttpStatusCode::isError,

                            // Función de manejo: La misma que teníamos antes
                            response ->
                                    response.bodyToMono(String.class)
                                            .defaultIfEmpty("[No error body provided from service]")
                                            .flatMap(errorBody -> {
                                                String errorMessage = "Service error: " + response.statusCode() + " - " + errorBody;
                                                RuntimeException exceptionToThrow = new RuntimeException(errorMessage);
                                                return Mono.error(exceptionToThrow);
                                            })
                    )
                    .toBodilessEntity() // No necesitamos el cuerpo de la respuesta, solo el éxito
                    .then(); // Convierte a Mono<Void> para indicar finalización


    }

    public Mono<Void> registerEmployee(RegisterEmployeeRequest request) {
        // 1. Validar el token de invitación
        ValidateInvitationDto validationPayload = new ValidateInvitationDto(request.getInvitationToken());

        return webClientBuilder.baseUrl(invitationServiceUrl).build()
                .post()
                .uri("/invitations/validate-and-consume") // Endpoint en NestJS para validar y consumir
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validationPayload)
                .retrieve()
                .onStatus(
                        HttpStatusCode::isError, // Captura errores 4xx y 5xx
                        response -> response.bodyToMono(String.class)
                                .defaultIfEmpty("[No error body provided from invitation validation service]")
                                .flatMap(errorBody -> {
                                    // Puedes ser más específico con el tipo de excepción si quieres
                                    String errorMessage = "Invitation token validation failed: " + response.statusCode() + " - " + errorBody;
                                    return Mono.error(new BadCredentialsException(errorMessage)); // O una excepción personalizada
                                })
                )
                .bodyToMono(ValidateInvitationResponse.class)
                .flatMap(validationResponse -> {

                    // 2. Si el token es válido, proceder con el registro del empleado
                    String hashedPassword = passwordEncoder.encode(request.getPassword());
                    EmployeeDTO employeeData = new EmployeeDTO(
                            request.getName(),
                            request.getLastName(),
                            request.getAge(),
                            request.getPhone(),
                            request.getEmail(),
                            hashedPassword,
                            request.getSedeId()
                    );

                    return webClientBuilder.baseUrl(employeeServiceUrl).build()
                            .post()
                            .uri("/employees") // Endpoint en EmployeeService para crear empleados
                            .contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(employeeData)
                            .retrieve()
                            .onStatus(
                                    HttpStatusCode::isError,
                                    empResponse -> empResponse.bodyToMono(String.class)
                                            .defaultIfEmpty("[No error body provided from employee service]")
                                            .flatMap(errorBody -> {
                                                String errorMessage = "Employee service error: " + empResponse.statusCode() + " - " + errorBody;
                                                // Considerar lógica de compensación si la creación del empleado falla
                                                // después de que el token de invitación fue consumido.
                                                return Mono.error(new RuntimeException(errorMessage));
                                            })
                            )
                            .toBodilessEntity()
                            .then(); // Convierte a Mono<Void>
                });
    }


    public Mono<AuthResponse> login(LoginRequest request) {
        // Determina a qué servicio preguntar (usando el userType del request)
        String targetServiceUrl;
        String targetUri;
        if ("client".equalsIgnoreCase(request.getUserType())) {
            targetServiceUrl = clientServiceUrl;
            targetUri = "/client/credentials"; // Endpoint para obtener credenciales por email
        } else if ("employee".equalsIgnoreCase(request.getUserType())) {
            targetServiceUrl = employeeServiceUrl;
            targetUri = "/employees/credentials"; // Endpoint similar en EmployeeService
        } else {
            return Mono.error(new IllegalArgumentException("Invalid user type"));
        }

        // Llama al servicio correspondiente para obtener las credenciales
        return webClientBuilder.baseUrl(targetServiceUrl).build()
                .post()
                .uri(targetUri)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .retrieve()
                // Manejo específico para 404 Not Found
                .onStatus(httpStatus -> httpStatus == HttpStatus.NOT_FOUND,
                        clientResponse -> Mono.error(new BadCredentialsException("User not found or invalid credentials")))
                // Manejo genérico para otros errores
                .onStatus(HttpStatusCode::isError,

                        // Función de manejo: La misma que teníamos antes
                        response ->
                                response.bodyToMono(String.class)
                                        .defaultIfEmpty("[No error body provided from service]")
                                        .flatMap(errorBody -> {
                                            String errorMessage = "Service error: " + response.statusCode() + " - " + errorBody;
                                            RuntimeException exceptionToThrow = new RuntimeException(errorMessage);
                                            return Mono.error(exceptionToThrow);
                                        })
                )
                // Convierte el cuerpo de la respuesta a un DTO esperado
                .bodyToMono(UserCredentialsDTO.class)
                // Una vez obtenidas las credenciales
                .flatMap(credentials -> {
                    // Compara la contraseña proporcionada con el hash almacenado
                    if (passwordEncoder.matches(request.getPassword(), credentials.getHashedPassword())) {
                        // Si coinciden, genera el JWT
                        String token = jwtTokenProvider.generateToken(credentials.getUserId(), credentials.getEmail(), credentials.getRoles());

                        AuthResponse authResponse = new AuthResponse(token);

                        return Mono.just(authResponse);
                    } else {
                        // Si no coinciden, error
                        return Mono.error(new BadCredentialsException("User not found or invalid credentials"));
                    }
                });
    }
}
