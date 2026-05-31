package ch.bbw.m183.vulnerapp.datamodel;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
@Entity
@Table(name = "users")
public class UserEntity {

	@Id
	@NotBlank
	@Size(min = 3, max = 32)
	@Pattern(regexp = "^[a-zA-Z0-9_.-]+$")
	String username;

	@Column(nullable = false)
	@NotBlank
	@Size(min = 1, max = 128)
	String fullname;

	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	@Column(nullable = false)
	@NotBlank
	String password;

	@Column(nullable = false)
	@NotBlank
	@Pattern(regexp = "^(USER|ADMIN)$")
	String role;
}
