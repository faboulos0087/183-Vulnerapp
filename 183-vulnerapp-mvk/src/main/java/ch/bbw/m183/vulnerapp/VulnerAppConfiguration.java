package ch.bbw.m183.vulnerapp;

import static org.springframework.data.web.config.EnableSpringDataWebSupport.PageSerializationMode.VIA_DTO;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Configuration
@EnableSpringDataWebSupport(pageSerializationMode = VIA_DTO)
public class VulnerAppConfiguration {

	@Bean
	public CommonsRequestLoggingFilter logFilter() {
		var filter = new CommonsRequestLoggingFilter();
		filter.setIncludeQueryString(false);
		filter.setIncludePayload(false);
		filter.setIncludeHeaders(false);
		filter.setBeforeMessagePrefix(">>>>> [");
		filter.setAfterMessagePrefix("<<<<< [");
		return filter;
	}
}
