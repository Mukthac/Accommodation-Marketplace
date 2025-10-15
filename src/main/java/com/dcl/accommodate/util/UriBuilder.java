package com.dcl.accommodate.util;

import org.springframework.stereotype.Component;

import java.net.URI;

@Component
public class UriBuilder {
    private String baseURI;

    public String buildPattern(String path){ return baseURI + path; }

    public URI buildURI(String path){
        return URI.create(baseURI + path);
    }

    public URI buildPublicURI(String path){
        return URI.create(baseURI + "/public" + path);
    }
}
