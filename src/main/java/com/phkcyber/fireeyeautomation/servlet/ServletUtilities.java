package com.phkcyber.fireeyeautomation.servlet;

import java.io.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletOutputStream;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

public class ServletUtilities {
  /**
   * Add headers for protection based on information from OWASP.
   *
   * @param response the response header
   */
  public static void addSecurityHeaders(HttpServletResponse response) {
    //click-jacking defense so content cannot be framed from a different website
    //response.addHeader("X-Frame-Options", "SAMEORIGIN");

    //forces client to only use content-type sent from server and not try to
    //determine the content type by magic sniffing
    //response.addHeader("X-Content-Type-Options", "nosniff");
  }



  /**
   * Wrapper method to send error to the client for use in pop-up error msgs
   */
  public static void sendError(HttpServletResponse response, String errorMsg) {
    PrintWriter out=null;

    try {
      response.setContentType("text/html");
      out = response.getWriter();

      if(out != null)
        out.println("<html><head><script>alert('" + errorMsg + "');</script></head><body></body></html>");
    }
    catch(Exception e) {
      e.printStackTrace();
    }
    finally {
      if(out != null)
        out.close();
    }
  }


  /**
   * Stream the image back to the requestor in the
   * format of a response.
   *
   * @param data the bytes of the report
   * @param response HTTP headers in servlet format
   */
  public static void streamFile(String filePath, HttpServletResponse response) {
    ServletOutputStream stream = null;
    FileInputStream f = null;
    BufferedInputStream buf = null;

    try {
      f = new FileInputStream( new File(filePath).getAbsolutePath());
      buf = null;

      stream = response.getOutputStream();

      buf = new BufferedInputStream(f);
      int readBytes = 0;

      //read from the file; write to the ServletOutputStream
      while ((readBytes = buf.read()) != -1)
        stream.write(readBytes);
    }
    catch (FileNotFoundException fnf) {
      fnf.getStackTrace();
    }
    catch (IOException ioe) {
      ioe.getStackTrace();
    }
    finally {
      try {
        if (stream != null)
          stream.close();
        if (buf != null)
           buf.close();
        if (f != null)
           f.close();
      }
      catch (IOException ioe) {
        ioe.getStackTrace();
      }
    }

  }

}
