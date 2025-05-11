package com.dev.security.Auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserCredentialsDTO {
    private UUID userId; // El ID único del usuario en su respectivo servicio
    private String email;
    private String hashedPassword;
    private List<String> roles; // Lista de roles/permisos
    // Getters y Setters
}