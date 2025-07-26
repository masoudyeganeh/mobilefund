package com.mobilefund.Redis.Config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.mobilefund.config.OtpContext;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

import java.io.IOException;

public class OtpContexRedisSerializer implements RedisSerializer<OtpContext> {
    private final ObjectMapper objectMapper;

    public OtpContexRedisSerializer() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Override
    public byte[] serialize(OtpContext context) throws SerializationException {
        try {
            return objectMapper.writeValueAsBytes(context);
        } catch (JsonProcessingException e) {
            throw new SerializationException("Error serializing OtpContext", e);
        }
    }

    @Override
    public OtpContext deserialize(byte[] bytes) throws SerializationException {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return objectMapper.readValue(bytes, OtpContext.class);
        } catch (IOException e) {
            throw new SerializationException("Error deserializing OtpContext", e);
        }
    }
}
