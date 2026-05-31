package ch.bbw.m183.vulnerapp.service;

import java.util.stream.Stream;

import ch.bbw.m183.vulnerapp.datamodel.UserCreateDto;
import ch.bbw.m183.vulnerapp.datamodel.UserEntity;
import ch.bbw.m183.vulnerapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@Transactional
@RequiredArgsConstructor
public class AdminService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@PreAuthorize("hasRole('ADMIN')")
	public UserEntity createUser(UserCreateDto dto) {
		return persistUser(dto);
	}

	@PreAuthorize("hasRole('ADMIN')")
	public Page<UserEntity> getUsers(Pageable pageable) {
		return userRepository.findAll(pageable);
	}

	@PreAuthorize("hasRole('ADMIN')")
	public void deleteUser(String username) {
		if (!userRepository.existsById(username)) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		}
		userRepository.deleteById(username);
	}

	private UserEntity persistUser(UserCreateDto dto) {
		if (userRepository.existsById(dto.getUsername())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT);
		}
		var user = new UserEntity()
				.setUsername(dto.getUsername())
				.setFullname(dto.getFullname())
				.setRole(dto.getRole())
				.setPassword(passwordEncoder.encode(dto.getPassword()));
		return userRepository.save(user);
	}

	@EventListener(ContextRefreshedEvent.class)
	public void loadTestUsers() {
		if (userRepository.count() > 0) {
			return;
		}
		Stream.of(
				new UserCreateDto()
						.setUsername("admin")
						.setFullname("Super Admin")
						.setPassword("Sup3rSecretAdmin")
						.setRole("ADMIN"),
				new UserCreateDto()
						.setUsername("fuu")
						.setFullname("Johanna Doe")
						.setPassword("BarbarossA123")
						.setRole("USER")
		).forEach(this::persistUser);
	}
}
