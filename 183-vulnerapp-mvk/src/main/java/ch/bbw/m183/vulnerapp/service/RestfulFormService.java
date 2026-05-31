package ch.bbw.m183.vulnerapp.service;

import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RestfulFormService {

    private final UserService userService;
    private final ObjectMapper objectMapper;

    public Customizer<FormLoginConfigurer<HttpSecurity>> restfulFormLogin() {
        return form -> form
                .failureHandler((req, res, ex) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .successHandler((request, response, auth) -> {
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType("application/json");
                    response.getWriter().write(
                            objectMapper.writeValueAsString(
                                    userService.whoami(auth.getName())
                            )
                    );
                });
    }

    public Customizer<ExceptionHandlingConfigurer<HttpSecurity>> unauthorizedPerDefault() {
        return ex -> ex.defaultAuthenticationEntryPointFor(
                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                request -> request.getRequestURI().startsWith("/api/")
        );
    }
}
