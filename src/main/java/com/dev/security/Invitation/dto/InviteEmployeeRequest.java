package com.dev.security.Invitation.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class InviteEmployeeRequest {
    private String invitedEmail;
    private String invitationType  = "EMPLOYEE_CANDIDATE";
}
