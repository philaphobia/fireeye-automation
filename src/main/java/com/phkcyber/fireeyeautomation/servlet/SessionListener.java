package com.phkcyber.fireeyeautomation.servlet;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

public class SessionListener implements HttpSessionListener {
 
  public void sessionCreated(HttpSessionEvent sessionEvent) {
    System.out.println("Session Created: Date=" + new java.util.Date() + " ID="+sessionEvent.getSession().getId());
  }
 
  public void sessionDestroyed(HttpSessionEvent sessionEvent) {
    System.out.println("Session Destroyed: Date=" + new java.util.Date() + " ID="+sessionEvent.getSession().getId());
 }
     
}
