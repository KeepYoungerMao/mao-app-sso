package com.mao.sso.auth.portal;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * 自助修改密码表单：需校验原密码，新密码两次输入一致（由 Controller 做一致性校验）。
 *
 * <p><b>只使用 {@code @Getter} / {@code @Setter}，禁止使用 {@code @Data}：</b>
 * {@code @Data} 生成的 {@code toString()} 会把明文密码写进日志。</p>
 */
@Getter
@Setter
public class ProfilePasswordForm {

	@NotBlank(message = "请输入当前密码")
	private String currentPassword;

	@NotBlank(message = "请输入新密码")
	@Size(min = 8, max = 64, message = "密码长度必须在 8~64 位之间")
	private String newPassword;

	@NotBlank(message = "请再次输入新密码")
	private String confirmPassword;

}
