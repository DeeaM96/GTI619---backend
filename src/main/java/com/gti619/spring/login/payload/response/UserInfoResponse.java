package com.gti619.spring.login.payload.response;

import java.util.Date;
import java.util.List;

public class UserInfoResponse {
	private Long id;
	private String username;
	private String email;
	private List<String> roles;

	private boolean blocked;


	private Date lastLogin;


	private Date loginAttempt;


	private Integer tentatives;

	public UserInfoResponse(Long id, String username, String email, List<String> roles) {
		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
	}

	public UserInfoResponse(Long id, String username, String email, List<String> roles, boolean blocked, Date lastLogin, Date loginAttempt, Integer tentatives) {
		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
		this.blocked = blocked;
		this.lastLogin = lastLogin;
		this.loginAttempt = loginAttempt;
		this.tentatives = tentatives;
	}

	public UserInfoResponse(Long id, String username, boolean blocked) {
		this.id = id;
		this.username = username;

		this.blocked = blocked;

	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	public boolean isBlocked() {
		return blocked;
	}

	public void setBlocked(boolean blocked) {
		this.blocked = blocked;
	}

	public Date getLastLogin() {
		return lastLogin;
	}

	public void setLastLogin(Date lastLogin) {
		this.lastLogin = lastLogin;
	}

	public Date getLoginAttempt() {
		return loginAttempt;
	}

	public void setLoginAttempt(Date loginAttempt) {
		this.loginAttempt = loginAttempt;
	}

	public Integer getTentatives() {
		return tentatives;
	}

	public void setTentatives(Integer tentatives) {
		this.tentatives = tentatives;
	}
}
