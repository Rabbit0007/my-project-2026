package demo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileService {
    private final Path uploadDir = Paths.get("/srv/app/uploads");

    public void save(String filename, byte[] body) throws Exception {
        Path target = Paths.get(uploadDir.toString(), filename);
        Files.write(target, body);
    }
}
