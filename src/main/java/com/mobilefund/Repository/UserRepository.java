package com.mobilefund.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.mobilefund.Model.User;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByPhoneNumber(String phoneNumber);

    Optional<User> findByNationalCode(String nationalCode);

    Boolean existsByPhoneNumber(String phoneNumber);

    Boolean existsByNationalCode(String nationalCode);
}
