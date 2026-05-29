package demo;

public class AdminExportService {
    public String exportUsers(String format, String includeInactive) {
        if (!"csv".equals(format) && !"json".equals(format)) {
            return "unsupported";
        }
        return "export:" + format + ":" + includeInactive;
    }
}
