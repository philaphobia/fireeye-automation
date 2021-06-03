package com.phkcyber.fireeyeautomation.pojo;

import java.util.Date;

import com.phkcyber.fireeyeautomation.common.Common;

public class Host {
	public String _id;
	public String agent_version;
	public Stats stats;
	public String hostname;
	public String domain;
	public String timezone;
	public String primary_ip_address;
	private String last_audit_timestamp;
	private String last_poll_timestamp;
	public String last_poll_ip;
	private String initial_agent_checking;
	public String url;
	public Alert last_alert;
	private String last_alert_timestamp;
	public Sysinfo sysinfo;
	public OS os;
	public String primary_mac;

	public Date getLastAuditTimeStamp() {
		return Common.parseDates(this.last_audit_timestamp);
	}
	
	public Date getLastPollTimestamp() {
		return Common.parseDates(this.last_poll_timestamp);
	}
	
	public Date getInitialAgentChecking() {
		return Common.parseDates(this.initial_agent_checking);
	}
	
	public Date getLastAlertTimestamp() {
		return Common.parseDates(this.last_alert_timestamp);
	}
	public class Stats {
		int acqs;
		int alerting_conditions;
		int alerts;
		int exploit_alerts;
		int exploit_blocks;
		int malware_alerts;
	}
	
	public class Alert {
		public String _id;
		public String url;
	}

	public class Sysinfo {
		public String url;
	}
	
	public class OS {
		public String product_name;
		public String patch_level;
		public String bitness;
		public String platform;
		public String kernel_version;
	}
	
}
