package com.mao.sso.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String username);

	Optional<User> findByEmail(String email);

	boolean existsByUsername(String username);

	boolean existsByEmail(String email);

	/**
	 * 按用户名查询并抓取角色。
	 */
	@Query("select u from User u left join fetch u.roles where u.username = :username")
	Optional<User> findByUsernameWithRoles(@Param("username") String username);

	/**
	 * 登录查询：用户名或邮箱匹配，并一次性抓取角色（避免懒加载 N+1）。
	 */
	@Query("select u from User u left join fetch u.roles where u.username = :identifier or u.email = :identifier")
	Optional<User> findByIdentifierWithRoles(@Param("identifier") String identifier);

	/**
	 * 按主键查询并抓取角色。
	 */
	@Query("select u from User u left join fetch u.roles where u.id = :id")
	Optional<User> findByIdWithRoles(@Param("id") Long id);

	/**
	 * 查询全部用户并抓取角色（管理页列表）。
	 */
	@Query("select distinct u from User u left join fetch u.roles order by u.id")
	java.util.List<User> findAllWithRoles();

}
