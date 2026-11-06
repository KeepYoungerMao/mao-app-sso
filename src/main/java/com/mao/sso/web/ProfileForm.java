package com.mao.sso.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * 个人资料表单（DTO 与 Entity 分离，承载 Bean Validation 约束）。
 */
public class ProfileForm {

	@NotBlank(message = "显示名称不能为空")
	@Size(max = 100, message = "显示名称长度不能超过 100")
	private String displayName;

	public String getDisplayName() {
		return this.displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

}
