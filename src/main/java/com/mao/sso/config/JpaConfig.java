package com.mao.sso.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * 启用 Spring Data JPA Auditing，为实体自动填充 created_at / updated_at。
 */
@Configuration
@EnableJpaAuditing
public class JpaConfig {

}
