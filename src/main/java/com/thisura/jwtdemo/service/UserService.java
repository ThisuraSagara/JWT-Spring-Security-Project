package com.thisura.jwtdemo.service;

import com.thisura.jwtdemo.domain.AppUser;
import com.thisura.jwtdemo.domain.Role;

import java.util.List;


public interface UserService {
    AppUser saveUser(AppUser appUser);

    Role saveRole(Role role);

    void addRoleToUser(String username, String rolename);

    AppUser getUser(String username);

    List<AppUser> getUsers();

}
