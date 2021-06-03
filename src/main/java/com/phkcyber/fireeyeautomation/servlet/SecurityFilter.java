package com.phkcyber.fireeyeautomation.servlet;

import com.phkcyber.fireeyeautomation.common.Utils;

import java.io.IOException;
import java.io.File;

import java.lang.IllegalStateException;

import java.util.*;
import java.util.regex.*;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.servlet.*;
import org.apache.commons.fileupload.disk.*;

public class SecurityFilter implements Filter {
  private Logger logger = Logger.getLogger(this.getClass());
  private ServletContext context=null;

  public void init(FilterConfig filterConfig) throws ServletException {
    //set the servlet context so it can be used in doFilter
    context = filterConfig.getServletContext(); 
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    logger.debug("doFilter()");
    HttpServletResponse resp = (HttpServletResponse) response;
    HttpServletRequest req = (HttpServletRequest) request;
    String servletPath = req.getServletPath();

    HttpSession session = req.getSession();
    String action=null;

    if(req.getMethod().equalsIgnoreCase("GET")) {
      String[] actionArr = (String[]) request.getParameterValues("action");
     
      if( (actionArr != null) && (actionArr.length > 0) )
        action=actionArr[0];
    } 

    else if(req.getMethod().equalsIgnoreCase("POST")) {

      //try to get action from paramater first
      if(request.getParameter("action") != null) {

        String[] actionArr = (String[]) request.getParameterValues("action");
     
        if( (actionArr != null) && (actionArr.length > 0) )
          action=actionArr[0];
      }

      //try for encode post upload
      else { 

        /**
         * Since the inputstream can only be read once, SecurityFilter will have to save
         * files to temp storage and variable to attributes so the ServletHandler can process
         * later.
         */
        try {
          Map<String, String[]> postFields = new HashMap<>();

          List<FileItem> items = new ServletFileUpload(new DiskFileItemFactory()).parseRequest(req);
   
          if(items == null)
            throw new ServletException("SecurityFilter error: cannot parse action from POST method.");
            
          for (FileItem item : items) {
            if (item.isFormField()) {
              if(item.getFieldName().equalsIgnoreCase("action")) {
                action = item.getString();

                //need to set action attribute since its encoded in the stream
                String[] tmpArr = new String[1];
                tmpArr[0] = action;
                postFields.put("action", tmpArr);
              }
              else {
                String[] tmpArr = new String[1];
                tmpArr[0] = item.getString();
                postFields.put(item.getFieldName(), tmpArr);
              }
            }
            else {
              //write the file to a temp location
              File tempFile = Utils.createTempFile("upload", ".tmp");
              item.write(tempFile);

              String[] newFiles=null;

              //no files yet so create a new array
              if(postFields.get("file_upload") == null) {
                newFiles = new String[1];
              }
              else {
                //get the array as a list
                List<String> tmpFileList = Arrays.asList( postFields.get("file_upload") );          

                //add and empty field at the end for the new file
                tmpFileList.add("");

                //convert list to an array
                newFiles = (String[]) tmpFileList.toArray();
              }

              //add this file to the end of the array
              newFiles[newFiles.length - 1] = tempFile.getAbsolutePath();
        
              //put files list map
              postFields.put("file_upload", newFiles);

            }//end else file upload

          }//end for FileItem

          //finished parsing all fields to put map into memory
          req.setAttribute("POST_FIELDS", postFields);

        }//end try
        catch(FileUploadException fue) {
          throw new ServletException("SecurityFilter error: cannot parse uploaded files.");
        }
        catch(Exception e) {
          throw new ServletException("SecurityFilter error: cannot write temp file.");
        }
    
      }//end else try encoded POST upload

    }//end POST method

    //unknown method
    else {
      throw new ServletException("SecurityFilter error: unknown method.");
    }

    
    if( (action == null) || (action.equals("")) ) {
      throw new ServletException("SecurityFilter error: cannot parse action.");
    }


    //extract the servlet name from the path
    String appName=null;
    Pattern pattern = Pattern.compile("^/apps/(.*)$");
    Matcher m=null;


    //instantiate the matcher
    m = pattern.matcher(servletPath);

    //match the path or throw exception
    if(m.find()) {
      appName=m.group(1);
    }
    else {
      logger.warn("SecurityFilter error: cannot parse path: " + servletPath);
      throw new ServletException("SecurityFilter error: cannot parse path: " + servletPath);
    } 

    //get the constructed AUTH init param
    String authPerms = "AUTH_PERMS_" + appName;

    //parse the value as a boolean
    Map<String, Map<String, Boolean>> authPermsMap = (Map<String, Map<String,Boolean>>) context.getAttribute(authPerms);

    //throw error if permissions are not retrieved
    if(authPermsMap == null) {
      logger.warn("SecurityFilter error: app permissions mapping is null");
      throw new ServletException("SecurityFilter error: app permissons mapping is null");
    } 

    //retrieve permissions for this action
    Map<String,Boolean> groupPermsMap = authPermsMap.get(action);

    //throw error if permissions are not retrieved for groups 
    if(groupPermsMap == null) {
      logger.warn("SecurityFilter error: action permissions mapping is null");
      throw new ServletException("SecurityFilter error: action permissons mapping is null");
    } 

    /**
     * Test permission to perform this action
     */
 
    //test action permitted by group 
    if(isAuthorized(session, groupPermsMap) ) {
      chain.doFilter(req, resp);
      return;
    }

    //test action authenticated only 
    else if( (groupPermsMap.get("AUTHENTICATED") != null) ) {
      if(isAuthenticated(session)) {
        chain.doFilter(req, resp);
        return;
      }
      else {
        resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User must login");
        return;
      }
    }

    //test action permitted by public
    else if( (groupPermsMap.get("PUBLIC") != null) && (groupPermsMap.get("PUBLIC")) ) {
      chain.doFilter(req, resp);
      return;
    }

    //user is not authorized send 403
    else {
      resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Not an authorized action");
      return;
    }

  }   


  private Boolean FAKEisAuthorized(HttpSession session, Map<String,Boolean> perms) {
    return(true);
  }

  private Boolean isAuthorized(HttpSession session, Map<String,Boolean> perms) {
    if( (session == null) || (perms == null) || (perms.size() == 0) )
      return(false);

    try {
      List<String> groups = (List<String>) session.getAttribute("groups");

      if(groups == null)
        return(false);

      for(String group : groups) {
        if( (perms.get(group) != null) && (perms.get(group)) ) 
          return(true);
      }
    }
    catch(IllegalStateException ise) {
      return(false);
    }

    //no matches so return false
    return(false);
  }


  private Boolean isAuthenticated(HttpSession session) {
    String token=null;

    try {
      token = (String) session.getAttribute("token");
    }
    catch(IllegalStateException ise) {
      return(false);
    }

    if (token != null) {
      return(true);
    }

    return(false);
  }

}
