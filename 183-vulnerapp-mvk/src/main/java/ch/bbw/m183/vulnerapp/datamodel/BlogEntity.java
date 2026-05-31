package ch.bbw.m183.vulnerapp.datamodel;

import java.time.LocalDateTime;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.hibernate.annotations.CreationTimestamp;

@Getter
@Setter
@Accessors(chain = true)
@Entity
@Table(name = "blogs")
public class BlogEntity {

	@Id
	@JsonProperty(access = JsonProperty.Access.READ_ONLY)
	UUID id;

	@Column(nullable = false)
	@CreationTimestamp
	@JsonProperty(access = JsonProperty.Access.READ_ONLY)
	LocalDateTime createdAt;

	@Column(nullable = false, columnDefinition = "text")
	@NotBlank
	@Size(min = 1, max = 200)
	String title;

	@Column(nullable = false, columnDefinition = "text")
	@NotBlank
	@Size(min = 1, max = 10000)
	String body;
}
