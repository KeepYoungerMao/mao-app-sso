package com.mao.sso.api.dto;

import com.mao.sso.domain.support.PageQuery;
import lombok.Getter;
import lombok.Setter;

/**
 * 客户端分页查询参数。
 */
@Getter
@Setter
public class ClientPageRequest extends PageQuery {

	/** 关键词：匹配 client_id / client_name。 */
	private String keyword;

}
