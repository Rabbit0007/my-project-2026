package demo;

import javax.servlet.http.HttpServletRequest;

public class AdminExportController {
    private final AdminExportService service = new AdminExportService();

    public String export(HttpServletRequest request) {
        String format = request.getParameter("format");
        String includeInactive = request.getParameter("includeInactive");
        return service.exportUsers(format, includeInactive);
    }
}
