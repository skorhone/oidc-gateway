package fi.kela.auth.identitygateway.json;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

@Service
public class JSONService {
	private ObjectReader objectReader;

	public JSONService() {
		this.objectReader = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
				.reader();
	}

	public <T> T readValue(InputStream is, Class<T> type) throws JsonProcessingException, IOException {
		return objectReader.forType(type).readValue(is);
	}

	public <T> T readValue(URL url, Class<T> type) throws JsonProcessingException, IOException {
		return objectReader.forType(type).readValue(url);
	}
}
