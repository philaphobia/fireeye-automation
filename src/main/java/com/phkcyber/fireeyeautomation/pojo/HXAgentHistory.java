package com.phkcyber.fireeyeautomation.pojo;

import java.util.Date;
import java.util.Map;

public class HXAgentHistory {
	private Map<String, HostAgent> hosts;
	
	public void setHost(Map<String, HostAgent> hosts) {
		this.hosts = hosts;
	}
	public Map<String, HostAgent> getHosts() {
		return(this.hosts);
	}
	
	public HostAgent newHostAgentInstance() {
		return new HostAgent();
	}
	
	public class HostAgent {
		public String ip;
		public String hostname;
		public Date first_added;
		public Date last_trigger;
		
		public HostAgent() {
			
		}
		
		public void setIp(String ip) {
			this.ip = ip;
		}
		public void setHostname(String hostname) {
			this.hostname = hostname;
		}
		public void setFirstAdded(Date first_added) {
			this.first_added = first_added;
		}
		public void setLastTrigger(Date last_trigger) {
			this.last_trigger = last_trigger;
		}
	}
}
