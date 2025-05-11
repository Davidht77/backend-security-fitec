package com.dev.security.Auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ClientDTO {
    private String name;
    private String lastName;
    private Integer age;
    private String phone;
    private String email;
    private String password; // Contraseña hasheada
    private String planName;
    // otros campos...
}