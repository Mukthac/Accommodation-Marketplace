package com.dcl.accommodate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class AccommodationMarketplaceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AccommodationMarketplaceApplication.class, args);
	}

}
