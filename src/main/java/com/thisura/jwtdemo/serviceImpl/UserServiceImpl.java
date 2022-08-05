package com.thisura.jwtdemo.serviceImpl;

import com.thisura.jwtdemo.domain.AppUser;
import com.thisura.jwtdemo.domain.Role;
import com.thisura.jwtdemo.repo.RoleRepo;
import com.thisura.jwtdemo.repo.UserRepo;
import com.thisura.jwtdemo.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
@Transactional
@Service
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    /**
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = userRepo.findByUsername(username);
        if (appUser == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found i the database: {}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        appUser.getRoles().forEach(role ->
        {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(appUser.getUsername(), appUser.getPassword(), authorities);
    }

    /**
     * @param appUser
     * @return
     */
    @Override
    public AppUser saveUser(AppUser appUser) {
        log.info("Saving new user  {} to the database", appUser.getName());
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return userRepo.save(appUser);
    }

    /**
     * @param role
     * @return
     */
    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role  {} to the database", role.getName());
        return roleRepo.save(role);
    }

    /**
     * @param username
     * @param roleName
     */
    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", username, roleName);
        Role role = roleRepo.findByName(roleName);
        AppUser appUser = userRepo.findByUsername(username);
        appUser.getRoles().add(role);
    }

    /**
     * @param username
     * @return User
     */
    @Override
    public AppUser getUser(String username) {
        log.info("Fetching user  {} from database", username);
        return userRepo.findByUsername(username);
    }

    /**
     * @return
     */
    @Override
    public List<AppUser> getUsers() {
        log.info("Fetching All Users");
        return userRepo.findAll();
    }


}
