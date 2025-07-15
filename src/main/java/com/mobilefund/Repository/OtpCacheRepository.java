package com.mobilefund.Repository;

import com.mobilefund.Model.OtpCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OtpCacheRepository extends JpaRepository<OtpCache, Integer> {
}
