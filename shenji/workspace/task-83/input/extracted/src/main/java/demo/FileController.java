package demo;

import org.springframework.web.multipart.MultipartFile;

public class FileController {
    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    public String upload(MultipartFile file) throws Exception {
        String filename = file.getOriginalFilename();
        fileService.save(filename, file.getBytes());
        return "ok";
    }
}
