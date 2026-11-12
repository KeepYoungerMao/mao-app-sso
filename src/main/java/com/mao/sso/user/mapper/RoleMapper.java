package com.mao.sso.user.mapper;

import java.util.List;
import java.util.Optional;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.mao.sso.user.Role;

/**
 * 角色持久化接口（SQL 定义见 {@code resources/mapper/RoleMapper.xml}）。
 */
@Mapper
public interface RoleMapper {

	Optional<Role> findById(@Param("id") Integer id);

	Optional<Role> findByCode(@Param("code") String code);

	List<Role> findAll();

	long count();

	int insert(Role role);

}
