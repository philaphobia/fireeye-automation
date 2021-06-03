package com.phkcyber.fireeyeautomation.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;

 
public class ITSecurityServletRequestListener implements ServletRequestListener {
 
  public void requestInitialized(ServletRequestEvent servletRequestEvent) {

    //create DB connection
    ServletContext ctx = servletRequestEvent.getServletContext();
  }


  public void requestDestroyed(ServletRequestEvent servletRequestEvent) {
  }
 
     
}
