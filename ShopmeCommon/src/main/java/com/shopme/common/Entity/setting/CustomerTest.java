package com.shopme.common.Entity.setting;

import com.shopme.common.entity.Customer;

public class CustomerTest {

    @Test
    public void test(){
        Customer customer= new Customer();
        customer.setEmail("email");
        customer.setEnabled(true);
        customer.setPassword("password");

        Assertions.assertEquals("email",customer.getEmail());
    }
}
