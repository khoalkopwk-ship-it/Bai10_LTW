package vn.iotstar.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RegisterUserDTO {

    @jakarta.validation.constraints.NotBlank
    @jakarta.validation.constraints.Email
    @jakarta.validation.constraints.Size(max = 100)
    private String email;
    @jakarta.validation.constraints.NotBlank
    @jakarta.validation.constraints.Size(min = 8, max = 64)
    private String password;
    @jakarta.validation.constraints.NotBlank
    @jakarta.validation.constraints.Size(max = 255)
    private String fullName;
}
