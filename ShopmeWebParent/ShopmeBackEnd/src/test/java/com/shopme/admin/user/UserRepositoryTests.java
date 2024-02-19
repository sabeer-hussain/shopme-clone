package com.shopme.admin.user;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.annotation.Rollback;

import com.shopme.common.entity.Role;
import com.shopme.common.entity.User;

@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
@Rollback(false)
public class UserRepositoryTests {
	@Autowired
	private UserRepository repo;
	
	@Autowired
	private TestEntityManager entityManager;
	
	@Test
	public void testCreateUserWithOneRole() {
		
		//will assign a role with id 1, which in the table would be admin
		Role roleAdmin = entityManager.find(Role.class,1);
		User user1 = new User("test@gmail.com","password1", "Smith", "John");
		user1.addRole(roleAdmin);
		
		User saveduser = repo.save(user1);
		
		assertThat(saveduser.getId()).isGreaterThan(0);
	}
	
	
	@Test
	public void testCreateUserWithTwoRoles() {
		
		User user1 = new User("bill@gmail.com","billpass", "Williams", "Bill");
		Role roleEditor = new Role(3);
		Role roleAsssist = new Role(5);
		user1.addRole(roleEditor);
		user1.addRole(roleAsssist);

		
		
		User saveduser = repo.save(user1);
		assertThat(saveduser.getId()).isGreaterThan(0);
	}
	
	@Test
	public void testListAllUsers() {
		
			Iterable<User> listUsers = repo.findAll();
			//will call the tostring method for every user
			listUsers.forEach(user -> System.out.println(user));
			
			
	}

	@Test
	public void testGetUserById() {
		
		User user1 = repo.findById(1).get();
		System.out.println(user1);
		assertThat(user1).isNotNull();
		
	}
	
	
	@Test
	public void testUpdateUserDetails() {
		

		User user1 = repo.findById(1).get();
		//by default user enable status is false
		user1.setEnabled(true);
		user1.setEmail("doge@yahoo.com");
		user1.setLastName("doge");
		
		repo.save(user1);
	}
	
	
	@Test
	public void testUpdateUserRoles() {
		
		User user2 = repo.findById(2).get();
		Role editor = new Role(3);
		Role salesman = new Role(2);
		
		user2.getRoles().remove(editor);
		user2.addRole(salesman);
	}
}
