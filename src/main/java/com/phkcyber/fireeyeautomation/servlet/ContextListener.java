package com.phkcyber.fireeyeautomation.servlet;
 
import java.util.Enumeration;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;


/**
 * Context Listener for deployment and destory of servlet
 */ 
public class ContextListener implements ServletContextListener {
 
  public void contextInitialized(ServletContextEvent servletContextEvent) {
    ServletContext context = servletContextEvent.getServletContext();

    Pattern patAuthPerms=null;;
    Matcher mAuth=null;
    Matcher mAuthPerms=null;

    for (Enumeration<String> e = context.getInitParameterNames(); e.hasMoreElements();) {
      String paramName = e.nextElement();

      patAuthPerms = Pattern.compile("^AUTH_PERMS_(.*)$");

      //instantiate the matcher
      mAuthPerms = patAuthPerms.matcher(paramName);
      String tmpStr = context.getInitParameter(paramName);

      //if param is an AUTH_PERMS 
      if(mAuthPerms.find()) {
       	context.setAttribute(paramName, parsePerms(tmpStr));
      }
      //everything else just set
      else {
        	context.setAttribute(paramName, tmpStr);
      }  

    }

    //start the TimerService which handles polling emails
    //TimerService timerService = new TimerService(context);
    //context.setAttribute("timer_service", timerService);

  }
 
  public void contextDestroyed(ServletContextEvent servletContextEvent) {
	  ServletContext context = servletContextEvent.getServletContext();
	  
	  //TimerService timerService = (TimerService) context.getAttribute("timer_service");
	  
	  //timerService.gracefulShutdown(context);
  }


  private static Map<String, Map<String, Boolean>> parsePerms(String authPermsStr) {
    String[] actions = authPermsStr.split("\\|");
    Map<String, Map<String, Boolean>> retVals = new HashMap<String, Map<String,Boolean>>();

    for(int i=0; i < actions.length; i++) {
      Pattern pattern = Pattern.compile("^(.*):(.*)$");
      Matcher m=null;

      //instantiate the matcher
      m = pattern.matcher(actions[i]);

      //match the user and list
      String action=null;
      String userList=null;

      //pattern match username:actions or skip and go to next for loop
      if(m.find()) {
        action=m.group(1);
        userList=m.group(2);
      }
      else {
        continue;
      }

      //next for loop if list is empty
      if( (action == null) || (action.equals("")) )
        continue;


      String[] users = userList.split(",");
      if(users.length <= 0)
        continue;

      //add each user to the user list
      Map<String,Boolean> usersMap = new HashMap<>();
      for(int j=0; j < users.length; j++) {
        usersMap.put(users[j], true);
      }

      if(users.length > 0)
        retVals.put(action, usersMap);
    }

    return(retVals);
  }

}
