package com.phkcyber.fireeyeautomation.servlet;

import com.phkcyber.fireeyeautomation.FireEye;

import java.io.*;
import java.util.logging.*;
import java.nio.charset.Charset;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.servlet.ServletContext;

import javax.servlet.http.HttpSession;

/**
 * Servlet Class to handle requests
 */
public class ServletHandler extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private Charset utfCharset=null;
	private Logger logger;

	/**
	 * @see HttpServlet#HttpServlet()
	*/
	public ServletHandler() {
		super();
		logger = Logger.getLogger("com.phkcyber.fireeyeautomation.servlet.ServletHandler"); 
	    
		try {
			utfCharset = Charset.forName("UTF-8");
		}
		catch(Exception e) {
			utfCharset=null;
		}
	}


	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		if(request == null) {
				sendError(response, "Error with session");
				throw new ServletException("HttpServletRequest is null");
		}

	    //get session from request
	    HttpSession session = request.getSession();
	    if(session == null) {
	      sendError(response, "Error with session");
	      throw new ServletException("HttpSession is null");
	    }
	 
	    ServletContext ctx = session.getServletContext();
	    if(ctx == null) {
	      sendError(response, "Error with session");
	      throw new ServletException ("ServletContext is null");
	    }


	    StringBuffer jb = new StringBuffer();
	    String line = null;
	    try {
	    	BufferedReader reader = request.getReader();
	    	while((line = reader.readLine()) != null) {
	    		jb.append(line);
	    	}
	    	
	    	System.out.println("JSON: " + jb.toString());
	    	FireEye fireeye = new FireEye();
	    	fireeye.process(jb.toString());
	    }
	    catch (Exception e) {
		StringWriter errors = new StringWriter();
	    	e.printStackTrace(new PrintWriter(errors));
		System.out.println("Caught Exception: " + errors.toString());

	    	e.printStackTrace();
	    }
	    
	    //verify database is setup
	    /**
	    mysql = (MySQLServletConnector) ctx.getAttribute("MySQLServletConnector");
	    if(mysql == null) {
	      sendError(response, "Error establishing connection to database");
	      throw new ServletException("mysql handler is null");
	    }
	    **/
	}

  /**
   * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
   */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		throw new ServletException("GET Request Disabled");
	}

  private void sendError(HttpServletResponse response, String errorMsg) {
    PrintWriter out=null;

    if(errorMsg == null)
      errorMsg="Unknown";

    try {
      response.setContentType("application/text");
      out = response.getWriter();
      out.println(errorMsg);
    }
    catch(Exception e) {
      logger.log(Level.FINE,"Debug",e);
    }
    finally {
      if(out != null)
        out.close();
    }
  }


}
