package com.phkcyber.fireeyeautomation.pojo;

import java.util.Date;

import com.google.gson.annotations.SerializedName;

import com.phkcyber.fireeyeautomation.common.Common;

public class InfectionMatch {
	public String msg;
	public String appliance;
	public String version;
	public String product;
	@SerializedName("appliance-id")
	public String applianceId;
	public Alert alert;
	
	public class Alert {
		public Host src;
		String product;
		public String name;
		public Host dst;
		String ack;
		String severity;
		public Explanation explanation;
		@SerializedName("alert-url")
		public String alerturl;
		@SerializedName("appliance-id")
		String applianceid;
		@SerializedName("root-infection")
		String root_infection;
		private String occurred;
		String action;
		String version;
		Interface iface;
		@SerializedName("sensor-ip")
		String sensorip;
		public String sensor;
		String id;
		String uuid;
	
		public class Host {
			public String ip;
			public String mac;
			public String vlan;
			public String port;
			public String host;
		}
		
		public class Explanation {
			@SerializedName("malware-detected")
			public MalwareDetected malwaredetected;
			@SerializedName("cnc-services")
			public CncServices cncservices;
			public String protocol;
			public String analysis;
			
			public class MalwareDetected {
				public Malware malware;
				
				public class Malware {
					public String name;
					public String stype;
					public String sid;
				}
			}
			
			public class CncServices {
				@SerializedName("cnc-service")
				public CncService cncservice;
				
				public class CncService {
					public String sname;
					String protocol;
					public String url;
					String address;
					String host;
					String side;
					public String type;
					String port;
					public String channel;
				}
			}
		}
		
		public class Interface {
			String iface;
			String mode;
			String label;
		}
		
		public Date getOccurred() {
			return( Common.parseDates(this.occurred) );
		}
		

	}//Alert
	
}
