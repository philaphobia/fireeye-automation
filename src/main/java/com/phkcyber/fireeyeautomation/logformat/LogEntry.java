package com.phkcyber.fireeyeautomation.logformat;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Abstract method to define the LogEntry structure and values that
 * are required. Each LogFormat type will implement their own based on
 * customized rules to parse the data in the given format;
 * 
 * @author Philip Kulp <philip.kulp@eassurellc.com>
 *
 */
public abstract class LogEntry {
	  protected SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
	  protected long itime=0L;
	  protected String type=null;
	  protected String utmEvent=null;
	  protected String src=null;
	  protected int srcPort=0;
	  protected String dst=null;
	  protected int dstPort=0;
	  protected String service=null;
	  protected int proto=0;
	  protected int duration=0;
	  protected String rule=null;
	  protected int sent=0;
	  protected int rcvd=0;
	  protected String action=null;
	  protected String status=null;
	  protected String utmAction=null;
	  protected String user=null;
	  protected String userOU=null;
	  protected String group=null;
	  protected String dstCountry=null;
	  protected String srcCountry=null;
	  protected String date=null;
	  protected String time=null;
	  protected Date dateTime=null;
	  protected String serial=null;
	  protected int application=0;

	  protected int policyId=99999;
	  protected String appCat=null;
	  protected String hostname=null;
	  protected String url=null;
	  protected String msg=null;
	  protected String method=null;
	  protected String catDesc=null;
	  
	  protected long bytes=0L;
	  protected int packets=0;
	  protected String flags=null;
	  
	  public LogEntry() {
		  //constructor for creating and empty object
	  }
	  
	  public LogEntry(String text) {
		  //constructor to be overloaded by child
	  }
	  
	  //itime
	  public void setItime(long itime) {
	    this.itime = itime;
	  }
	  public long getItime() {
	    return(this.itime);
	  }


	  //type
	  public void setType(String type) {
	    this.type = type;
	  }
	  public String getType() {
		  return(this.type);
	  }


	  //date
	  public void setDate(String date) {
	    this.date = date;
	  }
	  public String getDate() {
	    return(this.date);
	  }

	  
	  //time
	  public void setTime(String time) {
	    this.time = time;
	  }
	  public String getTime() {
	    return(this.time);
	  }


	  //dateTime
	  public void setDateTime(Date dateTime) {
		  //findbugs recommends storing new instance instead of reference
		  this.dateTime = new Date(dateTime.getTime());
	  }
  	  
	  public Date getDateTime() {
		  //date time is a date object from the combined date and time
		  //so if it hasn't been parsed yet perform the operations
		  if(this.dateTime == null) {
			try {
				String combined = this.date + " " + this.time;
			    this.dateTime = sdf.parse(combined);
			}
			catch(ParseException e) {
				this.dateTime=null;
				return(null);
			}
		}
		
	    //findbugs recommends returning new instance
	    return new Date(dateTime.getTime());
	  }

	  
	  //destination country
	  public void setDstCountry(String dstCountry) {
	    this.dstCountry = dstCountry;
	  }
	  public String getDstCountry() {
	    return(this.dstCountry);
	  }


	  //source country
	  public void setSrcCountry(String srcCountry) {
	    this.srcCountry = srcCountry;
	  }
	  public String getSrcCountry() {
	    return(this.srcCountry);
	  }

	  //user
	  public void setUser(String user) {
		  this.user = user;
	  }
	  public String getUser() {
		  return(this.user);
	  }
	  
	  
	  public void setUserOU(String userOU) {
		  this.userOU = userOU;
	  }
	  public String getUserOU() {
	      return(this.userOU);
	  }


	  //src
	  public void setSrc(String src) {
	    this.src = src;
	  }
	  public String getSrc() {
	    return(this.src);
	  }

	  
	  //srcPort
	  public void setSrcPort(int srcPort) {
	    this.srcPort = srcPort;
	  }
	  public int getSrcPort() {
	    return(this.srcPort);
	  }


	  //dst
	  public void setDst(String dst) {
	    this.dst = dst;
	  }
	  public String getDst() {
	    return(this.dst);
	  }


	  //dstPort
	  public void setDstPort(int dstPort) {
	    this.dstPort = dstPort;
	  }
	  public int getDstPort() {
	    return(this.dstPort);
	  }


	  //service
	  public void setService(String service) {
	    this.service = service;
	  }
	  public String getService() {
	    return(this.service);
	  }


	  //proto
	  public void setProto(int proto) {
	    this.proto = proto;
	  }
	  public int getProto() {
	    return(this.proto);
	  }


	  //duration
	  public void setDuration(int duration) {
	    this.duration = duration;
	  }
	  public int getDuration() {
	    return(this.duration);
	  }


	  //rule
	  public void setRule(String rule) {
	    this.rule = rule;
	  }
	  public String getRule() {
	    return(this.rule);
	  }


	  //sent
	  public void setSent(int sent) {
	    this.sent = sent;
	  }
	  public int getSent() {
	    return(this.sent);
	  }


	  //rcvd
	  public void setRcvd(int rcvd) {
	    this.rcvd = rcvd;
	  }
	  public int getRcvd() {
	    return(this.rcvd);
	  }


	  //serial
	  public void setSerial(String serial) {
	    this.serial = serial;
	  }
	  public String getSerial() {
	    return(this.serial);
	  }

	  //application
	  public void setApplication(String application) {
		try {
	   		this.application = Integer.parseInt(application);
		}
		catch(NumberFormatException nfe) {
			this.application = 0;
		}
	  }
	  public int getApplication() {
	    return(this.application);
	  }


	  //status
	  public void setStatus(String status) {
	    this.status = status;
	  }
	  public String getStatus() {
		  return(this.status);
	  }

	  //app cat
	  public void setAppCat(String appCat) {
	    this.appCat = appCat;
	  }
	  public String getAppCat() {
		  return(this.appCat);
	  }

	  //action
	  public void setAction(String action) {
	    this.action = action;
	  }
	  public String getAction() {
		  return(this.action);
	  }

	  //utm action
	  public void setUtmAction(String utmAction) {
	    this.utmAction = utmAction;
	  }
	  public String getUtmAction() {
		  return(this.utmAction);
	  }

	  //utm event
	  public void setUtmEvent(String utmEvent) {
	    this.utmEvent = utmEvent;
	  }
	  public String getUtmEvent() {
		  return(this.utmEvent);
	  }




	  //group
	  public void setGroup(String group) {
	      this.group=group;
	  }
	  public String getGroup() {
	      return(this.group);
	  }


	  //hostname
	  public void setHostname(String hostname) {
	    this.hostname = hostname;
	  }
	  public String getHostname() {
	    return(this.hostname);
	  }


	  //url
	  public void setUrl(String url) {
	    this.url = url;
	  }
	  public String getUrl() {
	    return(this.url);
	  }


	  //msg
	  public void setMsg(String msg) {
	    this.msg = msg;
	  }
	  public String getMsg() {
	    return(this.msg);
	  }


	  //method
	  public void setMethod(String method) {
	    this.method = method;
	  }
	  public String getMethod() {
	    return(this.method);
	  }


	  //cat_desc
	  public void setCatDesc(String catDesc) {
	    this.catDesc = catDesc;
	  }
	  public String getCatDesc() {
	    return(this.catDesc);
	  }
}
