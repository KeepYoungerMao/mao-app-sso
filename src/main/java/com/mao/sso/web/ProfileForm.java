package com.mao.sso.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * 个人资料表单（DTO 与 Entity 分离，承载 Bean Validation 约束）。
 */
@Getter
@Setter
public class ProfileForm {

	@NotBlank(message = "显示名称不能为空")
	@Size(max = 100, message = "显示名称长度不能超过 100")
	private String displayName;

}
