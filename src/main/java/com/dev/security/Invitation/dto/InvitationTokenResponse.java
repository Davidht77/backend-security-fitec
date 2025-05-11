package com.dev.security.Invitation.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class InvitationTokenResponse {
    private String token;
    private String invitedEmail;
    private String expiresAt; // Podría ser un String o un Date
}
