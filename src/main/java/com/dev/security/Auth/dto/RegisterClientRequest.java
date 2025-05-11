package com.dev.security.Auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegisterClientRequest {
    private String name;
    private String lastName;
    private Integer age;
    private String phone;
    private String email;
    private String password; // Contraseña en texto plano
    protected String planName;

    public Integer getAge() {
        return age;
    }
}
