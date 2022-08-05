package com.thisura.jwtdemo;

import com.thisura.jwtdemo.domain.AppUser;
import com.thisura.jwtdemo.domain.Role;
import com.thisura.jwtdemo.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableJpaRepositories
public class JwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

//	@Bean
//	CommandLineRunner runner(UserService userService) {
//		return args -> {
//			userService.saveRole(new Role(null, "ROLE_USER"));
//			userService.saveRole(new Role(null, "ROLE_MANAGER"));
//			userService.saveRole(new Role(null, "ROLE_ADMIN"));
//			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//
//			userService.saveUser(new AppUser(null, "John Silva", "john", "1234", new ArrayList<>()));
//			userService.saveUser(new AppUser(null, "Mahinda", "mahinda", "1234", new ArrayList<>()));
//			userService.saveUser(new AppUser(null, "Gota", "gota", "1234", new ArrayList<>()));
//			userService.saveUser(new AppUser(null, "Ranil", "ranil", "1234", new ArrayList<>()));
//
//			userService.addRoleToUser("john", "ROLE_USER");
//			userService.addRoleToUser("mahinda", "ROLE_MANAGER");
//			userService.addRoleToUser("gota", "ROLE_ADMIN");
//			userService.addRoleToUser("ranil", "ROLE_SUPER_ADMIN");
//			userService.addRoleToUser("ranil", "ROLE_ADMIN");
//			userService.addRoleToUser("ranil", "ROLE_USER");
//
//		};
//
//	}
}
