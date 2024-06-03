package com.codegym.service;

import com.codegym.model.Customer;

import java.util.List;

public interface ICustomerService {

    List<Customer> findAll();

    Customer findOne(Long id);

    void save(Customer customer);

    void delete(Long id);

}
