package com.dev.security.Invitation.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ValidateInvitationResponse {
    private boolean isValid;
    private String email;
}
