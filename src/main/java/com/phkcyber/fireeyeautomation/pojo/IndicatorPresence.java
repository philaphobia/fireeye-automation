package com.phkcyber.fireeyeautomation.pojo;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.List;

import com.google.gson.annotations.SerializedName;

public class IndicatorPresence {

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
			return( parseDates(this.event_at) );
		}
		
		public Date getMatchedAt() {
			return( parseDates(this.matched_at) );
		}
		
		public Date getReporteAt() {
			return( parseDates(this.reported_at) );
		}
		
		private Date parseDates(String strDate) {
			DateFormat dfWithMilli = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX");
			DateFormat dfWithoutMilli = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
			
			//with milli
			try {
				return dfWithMilli.parse(strDate);
			}
			catch (Exception e) {
				//ignore fail
			}
			
			//without milli
			try {
				return dfWithoutMilli.parse(strDate);
			}
			catch (Exception e) {
				//ignore faile
			}
			
			//no luck just return now
			return( new Date());
		}
		public class EventValues {
			DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
			
			@SerializedName("fileWriteEvent/timestamp")
			public String fileTimestamp;
			@SerializedName("fileWriteEvent/fullPath")
			public String fileFullPath;
			@SerializedName("fileWriteEvent/process")
			public String fileProcess;
			@SerializedName("fileWriteEvent/drive")
			public String fileDrive;
			@SerializedName("fileWriteEvent/fileName")
			public String fileFilename;
			@SerializedName("fileWriteEvent/username")
			public String fileUsername;
			@SerializedName("fileWriteEvent/size")
			public String fileSize;
			@SerializedName("fileWriteEvent/filePath")
			public String fileFilePath;
			@SerializedName("fileWriteEvent/pid")
			public String filePid;
			@SerializedName("fileWriteEvent/fileExtension")
			public String fileExtenszion;
			@SerializedName("fileWriteEvent/processPath")
			public String fileProcessPath;
			@SerializedName("fileWriteEvent/writes")
			public String fileWrites;
			@SerializedName("fileWriteEvent/closed")
			public String fileClosed;
			@SerializedName("fileWriteEvent/numBytesSeenWritten")
			public String fileNumbytesSeenWritten;
			
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
			
			
			Date getFileTimestamp() {
				try {
					return(df.parse(fileTimestamp));
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
