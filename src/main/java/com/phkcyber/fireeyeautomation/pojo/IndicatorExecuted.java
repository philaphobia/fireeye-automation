package com.phkcyber.fireeyeautomation.pojo;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.List;

import com.google.gson.annotations.SerializedName;

import common.Common;

public class IndicatorExecuted {
	public enum ALERT_METADATA {
		ALERT_URL,
		PRODUCT,
		ALERT_TYPE,
		DST_IP,
		ALERT_SEVERITY,
		SRC_IP,
		INDICATOR_NAME,
		TIMESTAMP
	}
	
	public String msg;
	public String appliance;
	public String version;
	public String product;
	@SerializedName("appliance-id")
	public String applianceId;
	public Alert alert;
	
	public class Alert {
		public String name;
		public String event_at;
		public String matched_at;
		public EventValues event_values;
		public Host host;
		public Condition condition;
		public String reported_at;
		public String resolution;
		public String source;
		public String event_type;
		public List <MatchedSourceAlerts> matched_source_alerts;
		public String event_id;
		public String uuid;
		
		//dates in JSON are inconsistent so need to parse
		public Date getEventAt() {
			return( Common.parseDates(this.event_at) );
		}
		
		public Date getMatchedAt() {
			return( Common.parseDates(this.matched_at) );
		}
		
		public Date getReporteAt() {
			return( Common.parseDates(this.reported_at) );
		}
		

		public class EventValues {
			DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
			
			@SerializedName("urlMonitorEvent/timestamp")
			public String urlTimestamp;
			@SerializedName("urlMonitorEvent/remoteIpAddress")
			public String urlDstIp;
			@SerializedName("urlMonitorEvent/urlMethod")
			public String urlMethod;
			@SerializedName("urlMonitorEvent/hostname")
			public String urlHostname;
			@SerializedName("urlMonitorEvent/process")
			public String urlProcess;
			@SerializedName("urlMonitorEvent/username")
			public String urlUsername;
			@SerializedName("urlMonitorEvent/requestUrl")
			public String urlRequestUrl;
			@SerializedName("urlMonitorEvent/httpdHeader")
			public String urlHttpHeader;
			@SerializedName("urlMonitorEvent/localPort")
			public String urlLocalPort;
			@SerializedName("urlMonitorEvent/userAgent")
			public String urlUserAgent;
			@SerializedName("urlMonitorEvent/remotePort")
			public String urlRemotePort;
			@SerializedName("urlMonitorEvent/pid")
			public String urlPid;
			@SerializedName("urlMonitorEvent/processPath")
			public String urlProcessPath;
			
			//IOC alert values
			@SerializedName("ipv4NetworkEvent/timestamp")
			public String netTimestamp;
			@SerializedName("ipv4NetworkEvent/remoteIP")
			public String netDstIp;
			@SerializedName("ipv4NetworkEvent/process")
			public String netProcess;
			@SerializedName("ipv4NetworkEvent/remotePort")
			public String netDstPort;
			@SerializedName("ipv4NetworkEvent/localIp")
			public String netSrcIp;
			@SerializedName("ipv4NetworkEvent/localPort")
			public String netSrcPort;
			@SerializedName("ipv4NetworkEvent/pid")
			public String netPid;
			@SerializedName("ipv4NetworkEvent/processPath")
			public String netProcessPath;
			@SerializedName("ipv4NetworkEvent/username")
			public String netUsername;
			
			
			Date getUrlTimestamp() {
				try {
					return(df.parse(urlTimestamp));
				}
				catch(Exception e) {
					return(new Date());
				}
			}
			
			Date getNetTimestamp() {
				try {
					return(df.parse(netTimestamp));
				}
				catch(Exception e) {
					return(new Date());
				}
			}
			
		}
		
		public class Host {
			public String hostname;
			public String agent_version;
			public String ip;
			public String containment_state;
			public String os;
			public String agent_id;
		}
		
		public class Condition {
			public List<Test> tests;
			
			public class Test {
				public String type;
				public String operator;
				public String preservecase;
				public String token;
				public String value;
			}
		}
		
		public class MatchedSourceAlerts {
			public int row;
			public int _id;
			public String appliance_id;
			public String url;
			public Meta meta;
			public String indicator_name;
			public String indicator_id;
			public String indicator_revision;
			public String indicator_category_name;
			
			public class Meta {
				public String product_name;
				public String alert_id;
				public String alert_type;
				public String dst_ip;
				public String lms_iden;
				public String alert_severity;
				public String alert_timestamp;
				public String src_ip;
				
				public Date getTimestamp() {
					DateFormat dfWithMilli = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX");
					DateFormat dfWithoutMilli = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
					
					//with milli
					try {
						return dfWithMilli.parse(this.alert_timestamp);
					}
					catch (Exception e) {
						//ignore fail
					}
					
					//without milli
					try {
						return dfWithoutMilli.parse(this.alert_timestamp);
					}
					catch (Exception e) {
						//ignore faile
					}
					
					//no luck just return now
					return( new Date());
				}
			}
		}
	}
}
