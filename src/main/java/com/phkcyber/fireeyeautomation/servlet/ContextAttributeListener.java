package com.phkcyber.fireeyeautomation.servlet;

import javax.servlet.ServletContextAttributeEvent;
import javax.servlet.ServletContextAttributeListener;
 
public class ContextAttributeListener implements ServletContextAttributeListener {
 
  public void attributeAdded(ServletContextAttributeEvent servletContextAttributeEvent) {
    System.out.println("ServletContext attribute added::{"+servletContextAttributeEvent.getName()+","+servletContextAttributeEvent.getValue()+"}");
  }
 
  public void attributeReplaced(ServletContextAttributeEvent servletContextAttributeEvent) {
    System.out.println("ServletContext attribute replaced::{"+servletContextAttributeEvent.getName()+","+servletContextAttributeEvent.getValue()+"}");
  }
 
  public void attributeRemoved(ServletContextAttributeEvent servletContextAttributeEvent) {
    System.out.println("ServletContext attribute removed::{"+servletContextAttributeEvent.getName()+","+servletContextAttributeEvent.getValue()+"}");
  }
     
}
