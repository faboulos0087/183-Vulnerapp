package ch.bbw.m183.vulnerapp.datamodel;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
public class UserCreateDto {

	@NotBlank
	@Size(min = 3, max = 32)
	@Pattern(regexp = "^[a-zA-Z0-9_.-]+$")
	private String username;

	@NotBlank
	@Size(min = 1, max = 128)
	private String fullname;

	@NotBlank
	@Size(min = 10, max = 128)
	@Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$",
			message = "password must contain lower-case, upper-case and a digit")
	private String password;

	@NotBlank
	@Pattern(regexp = "^(USER|ADMIN)$")
	private String role;
}
