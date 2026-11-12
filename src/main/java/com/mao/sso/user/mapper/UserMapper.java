package com.mao.sso.user.mapper;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.mao.sso.user.User;

/**
 * 用户持久化接口（SQL 定义见 {@code resources/mapper/UserMapper.xml}）。
 *
 * <p>命名约定：</p>
 * <ul>
 *   <li>{@code ...WithRoles}：一次 join 抓取用户及其角色，用于登录、详情等需要完整对象的场景；</li>
 *   <li>{@code selectPage / countPage}：管理列表分页，角色由 Service 二次批量查询组装。</li>
 * </ul>
 */
@Mapper
public interface UserMapper {

	// ---------- 查询 ----------

	Optional<User> findById(@Param("id") Integer id);

	Optional<User> findByUsername(@Param("username") String username);

	Optional<User> findByIdWithRoles(@Param("id") Integer id);

	Optional<User> findByUsernameWithRoles(@Param("username") String username);

	/** 登录查询：用户名或邮箱均可。 */
	Optional<User> findByIdentifierWithRoles(@Param("identifier") String identifier);

	List<User> findAllWithRoles();

	List<User> selectPage(@Param("keyword") String keyword, @Param("enabled") Boolean enabled,
			@Param("locked") Boolean locked, @Param("offset") int offset, @Param("limit") int limit);

	long countPage(@Param("keyword") String keyword, @Param("enabled") Boolean enabled,
			@Param("locked") Boolean locked);

	/** 批量查询多个用户的角色（两段式分页组装的第二段）。 */
	List<UserRoleRow> findRolesByUserIds(@Param("ids") List<Integer> ids);

	long countByUsername(@Param("username") String username, @Param("excludeId") Integer excludeId);

	long countByEmail(@Param("email") String email, @Param("excludeId") Integer excludeId);

	/** 统计「启用且未锁定」的管理员数量，用于最后管理员保护。 */
	long countActiveAdmins(@Param("excludeId") Integer excludeId);

	long count();

	// ---------- 写入 ----------

	int insert(User user);

	int updateProfile(@Param("id") Integer id, @Param("email") String email, @Param("phone") String phone,
			@Param("avatar") String avatar, @Param("displayName") String displayName,
			@Param("updatedBy") String updatedBy);

	int updatePassword(@Param("id") Integer id, @Param("passwordHash") String passwordHash,
			@Param("mustChangePassword") boolean mustChangePassword, @Param("updatedBy") String updatedBy);

	int updateStatus(@Param("id") Integer id, @Param("enabled") boolean enabled,
			@Param("accountLocked") boolean accountLocked, @Param("updatedBy") String updatedBy);

	int updateCredentialsExpiredAt(@Param("id") Integer id,
			@Param("credentialsExpiredAt") Instant credentialsExpiredAt, @Param("updatedBy") String updatedBy);

	int updateLastLoginAt(@Param("id") Integer id, @Param("lastLoginAt") Instant lastLoginAt);

	int deleteById(@Param("id") Integer id);

	int deleteUserRoles(@Param("userId") Integer userId);

	int insertUserRoles(@Param("userId") Integer userId, @Param("roleIds") List<Integer> roleIds);

}
