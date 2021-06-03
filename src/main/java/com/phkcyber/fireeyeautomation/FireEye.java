package com.phkcyber.fireeyeautomation;

import com.phkcyber.fireeyeautomation.common.Common;
import com.phkcyber.fireeyeautomation.common.Email;
import com.phkcyber.fireeyeautomation.pojo.ExploitBlocked;
import com.phkcyber.fireeyeautomation.pojo.ExploitBlocked.Alert.EventValues.AnalysisDetail;
import com.phkcyber.fireeyeautomation.pojo.FireEyeAlert;
import com.phkcyber.fireeyeautomation.pojo.Host;
import com.phkcyber.fireeyeautomation.pojo.HostSet;
import com.phkcyber.fireeyeautomation.pojo.IndicatorExecuted;
import com.phkcyber.fireeyeautomation.pojo.IndicatorPresence;
import com.phkcyber.fireeyeautomation.pojo.InfectionMatch;
import com.phkcyber.fireeyeautomation.pojo.MalwareObject;
import com.phkcyber.fireeyeautomation.netflow.Netflow;
import com.phkcyber.fireeyeautomation.virustotal.VirusTotal;

import java.io.*;
import java.util.*;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.phkcyber.fireeyeautomation.writer.ExcelWriter;


public class FireEye {
	private DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
	private String dateMatch = "yyyy-MM-dd'T'HH:mm:ss.SSSX";
	private String vtFile=null;
	private String netflowFile=null;

	private String[] to= {};
	private String from = "";

	public FireEye() {
		//instantiate
	}

	public void process(String json) throws Exception {
		Map<KEY,String> parsed = parseJson(json);
		String infectedIp = parsed.get(KEY.SRC_IP);
		String agentId = parsed.get(KEY.AGENT_ID);
		
		HX hx = null;
		try {
			//get new HX instance
			hx = new HX();
			hx.login();
			
			//get host in malware hostset
			HostSet malwareHostset = hx.getHostsFromHostSet();
			List<Host> hosts = malwareHostset.data.entries;
			
			
			//check if infected host already in malware list
			Host matched=null;
			for(Host host : hosts) {
				//try to match my agent id 
				if(agentId != null && agentId.equals(host._id)) {
					matched=host;
					break;
				}
				//try to match by IP
				else if(infectedIp.equals(host.primary_ip_address)) {
					matched=host;
					break;
				}
			}
			
			//not found in malware hostset so add
			StringBuffer details = new StringBuffer();
			if(matched == null) {
				details.append("<br>HX agent not in malware scan hostset.");
				
				//if agent id is available just add
				if(agentId != null) {
					try {
						boolean added = hx.addHostToHostset(agentId);
						if(! added)
							throw new Exception("no exception caught - just soft fail");
						
						details.append("<br>Successfully added agent with id: " + agentId + " to malware scan hostset");
					}
					catch (Exception e) {
						details.append("<br>Failed to add agent with id: " + agentId + " to malware scan hostset error: " + e.getMessage());
					}
				}
				
				//search for agent
				else {
					List<Host> searchHosts = hx.searchHosts(infectedIp);
					details.append("<br>HX API search found " + searchHosts.size() + " matching agent(s).");
					
					Host tmpHost=null;
					//loop through hosts from search
					if(searchHosts.size() > 0) {
						tmpHost = searchHosts.get(0);
						
						//loop to find the agent which has been polled most recently
						for(Host host : searchHosts) {
							//update matched if
							if(tmpHost.getLastPollTimestamp().before(host.getLastPollTimestamp()))
								tmpHost = host;
							
							try {
								boolean added = hx.addHostToHostset(host._id);
								if(! added)
									throw new Exception("no exception caught - just soft fail");
								
								details.append("<br>Successfully added searched agent with id: " + host._id + " to malware scan hostset");
							}
							catch (Exception e) {
								details.append("<br>Failed to add searched agent with id: " + host._id + " to malware scan hostset error: " + e.getMessage());
							}
								
						}
						
						updateHostInfo(tmpHost, parsed);

					}//if searcHost size
				}//else search agent Id
			}
			else {
				details.append("<br>HX agent already in malware scan hostset.");
				
				updateHostInfo(matched, parsed);
			}

			//send email
			sendEmail(parsed, details.toString());
		}
		catch(Exception e) {
	                StringWriter errors = new StringWriter();
        	        e.printStackTrace(new PrintWriter(errors));
                	System.out.println("Caught Exception: " + errors.toString());
		}
		finally {
			//catch and ignore logout errors
			try {
				if(hx != null)
				hx.logout();
			}
			catch(Exception e) {
				System.out.println("Caught and ignore exception on logout" + e.getMessage());
			}
		}
	}
	
	
	public void updateHostInfo(Host tmpHost, Map<KEY,String> parsed) {
		String os = tmpHost.os.product_name;
		String patch_level = tmpHost.os.patch_level;

		
		if(os == null)
			os = "Unknown";
		if(patch_level == null)
			patch_level = "Unknown";
		
		if(parsed.get(KEY.HOST_OS) == null)
			parsed.put(KEY.HOST_OS, os + " " + patch_level);
		
		if(parsed.get(KEY.HOST_AGENT)== null)
			parsed.put(KEY.HOST_AGENT, tmpHost.agent_version);
		
		if(parsed.get(KEY.HOST_DOMAIN)== null)
			parsed.put(KEY.HOST_DOMAIN, tmpHost.domain);
		
		if(parsed.get(KEY.HOST_HOSTNAME)== null)
			parsed.put(KEY.HOST_HOSTNAME, tmpHost.hostname);
		
		if(parsed.get(KEY.HOST_TIMEZONE) == null)
			parsed.put(KEY.HOST_TIMEZONE, tmpHost.timezone);
		
		if(parsed.get(KEY.HOST_LAST)== null)
			parsed.put(KEY.HOST_LAST, df.format( tmpHost.getLastPollTimestamp()));
	}
	
	
	public void sendEmail(Map<KEY,String> parsed, String details) throws Exception {

		//create body data
		String srcIp = (parsed.get(KEY.SRC_IP) != null ? parsed.get(KEY.SRC_IP) : "N/A");
		String srcPort = (parsed.get(KEY.SRC_PORT) != null ? parsed.get(KEY.SRC_PORT) : "N/A");
		String dstIp = (parsed.get(KEY.DST_IP) != null ? parsed.get(KEY.DST_IP) : "N/A");
		String dstPort = (parsed.get(KEY.DST_PORT) != null ? parsed.get(KEY.DST_PORT) : "N/A");
		String alertUrl = (parsed.get(KEY.ALERT_URL) != null ? parsed.get(KEY.ALERT_URL) : "N/A");
		String timestamp = (parsed.get(KEY.OCCURRED) != null ? parsed.get(KEY.OCCURRED) : "N/A");
		String sensor = (parsed.get(KEY.SENSOR) != null ? parsed.get(KEY.SENSOR) : "N/A");
		String username = (parsed.get(KEY.USERNAME) != null ? parsed.get(KEY.USERNAME) : "N/A");
		String malwareData = (parsed.get(KEY.MALWARE_DATA) != null ? parsed.get(KEY.MALWARE_DATA) : "N/A");
		
		//only build process variable if at least process is defined
		String process = null;
		if(parsed.get(KEY.PROCESS) != null) {
			if(parsed.get(KEY.PROCESS_PATH) != null) {
				process = parsed.get(KEY.PROCESS_PATH) + "\\" + parsed.get(KEY.PROCESS);
			}
			else {
				process = parsed.get(KEY.PROCESS);
			}
		}
		
		//malware
		String malware=null;
		if( parsed.get(KEY.MALWARE_NAME) != null && parsed.get(KEY.MALWARE_TYPE) != null) {
			malware = parsed.get(KEY.MALWARE_NAME) + " : " + parsed.get(KEY.MALWARE_TYPE);
		}
	
		//CNC name
		String cncName=null;
		if(parsed.get(KEY.CNC_NAME) != null && parsed.get(KEY.CNC_TYPE) != null) {
			cncName = parsed.get(KEY.CNC_NAME) + " : " + parsed.get(KEY.CNC_TYPE);
		}
		
		//CNC Url
		String cncUrl = (parsed.get(KEY.CNC_URL) != null ? parsed.get(KEY.CNC_URL) : null);
	
		//format CNC data text
		String cncData = parsed.get(KEY.CNC_DATA);
		if(cncData != null) {
			cncData.trim();
			if(cncData.isEmpty()) {
				cncData = null;
			}
			else {
				cncData = cncData.replace("::~~", "\n");
			}
		}
		
		//action
		String action = (parsed.get(KEY.ACTION) != null ? parsed.get(KEY.ACTION) : null);
		String analysis = (parsed.get(KEY.ANALYSIS) != null ? parsed.get(KEY.ANALYSIS) : null);
		
		//build Email object
		Email email = new Email();
		email.addFrom(from);
		email.addTo(Arrays.asList(to));
		email.addSubject( generateSubject(parsed) );
		
		//create body
		StringBuffer body = new StringBuffer();
		body.append("<br><strong>Timestamp</strong>: " + timestamp);
		body.append("<br><strong>Src IP</strong>: " + srcIp);
		body.append("<br><strong>Src Port</strong>: " + srcPort);
		body.append("<br><strong>Dst IP</strong>: " + dstIp);
		body.append("<br><strong>Dst Port</strong>: " + dstPort);
		body.append("<br><strong>Username</strong>: " + username);
		
		body.append("<br/>");
		
		body.append("<br><strong>Sensor</strong>: " + sensor);
		body.append("<br><strong>Process</strong>: " + process);
		body.append("<br><strong>Alert Url</strong>: " + alertUrl);
		
		body.append("<br/>");
		
		body.append("<br><strong>Infection Name</strong>: " + parsed.get(KEY.INFECTION_NAME));
		
		if(malware != null) {
			body.append("<br><strong>Malware Name/Type</strong>: " + malware);
		}
		
		if(cncName != null) {
			body.append("<br><strong>CNC Name/Type</strong>: " + cncName);
		}
		
		if(cncUrl != null) {
			body.append("<br><strong>Malicious Url</strong>: " + cncUrl);
		}
		
		if(action != null) {
			body.append("<br><strong>Action</strong>: " + action);
		}
		
		if(analysis != null) {
			body.append("<br><strong>Analysis</strong>: " + analysis);
		}
		
		if(cncData != null) {
			body.append("<br><strong>Malicious Data</strong>: <br><pre>" + cncData + "</pre>");
		}

		if(malwareData != null) {
			body.append("<br><strong>Malware Data</string>: <br>" + malwareData + "</br>");

		}
		
		body.append("<br/>");
		
		//add agent details known
		if(parsed.get(KEY.HOST_HOSTNAME) != null)
			body.append("<br><strong>Hostname</strong>: " + parsed.get(KEY.HOST_HOSTNAME));
		if(parsed.get(KEY.HOST_OS) != null)
			body.append("<br><strong>Host OS</strong>: " + parsed.get(KEY.HOST_OS));
		if(parsed.get(KEY.HOST_AGENT) != null)
			body.append("<br><strong>HX Agent Version</strong>: " + parsed.get(KEY.HOST_AGENT));
		if(parsed.get(KEY.HOST_DOMAIN) != null)
			body.append("<br><strong>Domain</strong>: " + parsed.get(KEY.HOST_DOMAIN));
		if(parsed.get(KEY.HOST_TIMEZONE) != null)
			body.append("<br><strong>Timezone</strong>: " + parsed.get(KEY.HOST_TIMEZONE));
		if(parsed.get(KEY.HOST_LAST) != null)
			body.append("<br><strong>Last Agent Check-in</strong>: " + parsed.get(KEY.HOST_LAST));
		
		body.append("<br><br><strong>Additional details</strong>:");
		body.append(details);

		
		List<Map<String,Object>> logs = null;
	
		if(srcIp != null && dstIp != null) {
			//get Netflow
			try {
				//check if IP in our CIDRs availabe in Netflow before searching
				if( (! srcIp.startsWith("10.")) && (! srcIp.startsWith("207.245.160.")) ) {
					if( (! dstIp.startsWith("10.")) && (! dstIp.startsWith("207.245.160.")) ) {
						logs=null;

						//return;
						throw new Exception("<br>Src: " + srcIp + " Dst: " + dstIp + " are not in the Netflow CIDR range</br>");
					}
				}
				//get logs if needed
				Netflow netflow = new Netflow();

				logs = netflow.searchFireEyeAlert(parsed.get(KEY.OCCURRED), srcIp, dstIp);

				if(logs.size() > 0) {
					ExcelWriter writer = new ExcelWriter();
					writer.addRows(logs);
					netflowFile = writer.writeFile();
				}
				else {
					body.append("<br>No Netflow logs found to attach</br>");
				}
			}
			catch(Exception e) {
				logs = null;
				StringWriter sw = new StringWriter();
				PrintWriter pw = new PrintWriter(sw);
				e.printStackTrace(pw);
				
				//body.append("<br>Caught exception attempting to download Netflow logs: " + sw.toString() + "</br>");
				body.append("<br>Caught exception attempting to download Netflow logs: " + e.getMessage() + "</br>");
			}

		}
		else {
			logs = null;
			body.append("<br>No Src or Dst. Not attaching logs.</br>");
		}
	
		email.addBody(body.toString());

		//add attachments if needed	
		HashMap<String,String> attachments = new HashMap<>();
		if(vtFile != null) {
			attachments.put(vtFile,"virus_total.json.txt");
		}
 
		if(logs != null && logs.size() > 0) {	
			attachments.put(netflowFile, "netflow.xlsx");
		}

		//add attachments if at least 1 was created
		if(attachments.size() > 0) {
			email.addAttachments(attachments);
		}
		
		//send email
		email.sendMessage();
	}
	
	
	private String generateSubject(Map<KEY,String> parsed) {
		String subject = parsed.get(KEY.INFECTION_NAME) + " detected: " + parsed.get(KEY.SRC_IP) + " (processed)";
		return(subject);
	}
	
	private Map<KEY,String> parseJson(String json) throws Exception {
		if(json == null)
			throw new Exception ("JSON string is null");
		

		Gson gson = new GsonBuilder().setDateFormat(dateMatch).create();
	
		//parse a generic FireEyeAlert to determine specific type
		FireEyeAlert fireeyeAlert = gson.fromJson(json, FireEyeAlert.class);

		//check if object parsed null
		if(fireeyeAlert == null) 
			throw new Exception("Parsed JSON is null");
			
		//check for alert class
		if(fireeyeAlert.alert == null)
			throw new Exception ("No alert object");
		
		//check for alert name
		if(fireeyeAlert.alert.name == null)
			throw new Exception("No alert name");
	
		System.out.println("Parsing FireEye Alert");
		//determine the alert type
		switch(fireeyeAlert.alert.name) {
			case "infection-match":
				System.out.println("Identified INFECTION-MATCH alert");
				return parseJsonInfectionMatch(json);

			case "indicator-executed":
				System.out.println("Identified INDICATOR-EXECUTE alert");
				return parseJsonIndicatorExecuted(json);
				
			case "indicator-presence":
				System.out.println("Identified INDICATOR-PRESENCE alert");
				return parseJsonIndicatorPresence(json);
				
			case "malware-object":
				System.out.println("Identified MALWARE-OBJECT alert");
				return parseJsonMalwareObject(json);
				
			case "exploit-blocked":
				System.out.println("Identified EXPLOIT-BLOCKED alert");
				return parseJsonExploitBlocked(json);
				
			case "malware-callback":
				System.out.println("Identified MALWARE-CALLBACK alert");
				//Same schema as InfectionMatch so use that format
				return parseJsonInfectionMatch(json);
				
			default:
				throw new Exception("Unknown alert name: " + fireeyeAlert.alert.name);
		}
		
	}
		
	
	private Map<KEY,String> parseJsonIndicatorExecuted(String json) throws Exception {
		Map<KEY,String> parsed = new HashMap<>();
		
		Gson gson = new GsonBuilder().setDateFormat(dateMatch).create();
		
		IndicatorExecuted indicatorExecuted = gson.fromJson(json, IndicatorExecuted.class);
		
		//verify json parsed
		if(indicatorExecuted == null)
			throw new Exception("Parsed JSON is null");
		
		//verify alert available
		if(indicatorExecuted.alert == null)
			throw new Exception("No alert object");
	
		//verify event_values available
		if(indicatorExecuted.alert.event_values == null)
			throw new Exception("No event values");
		
		//get source IP
		if(indicatorExecuted.alert.host.ip != null)
			parsed.put(KEY.SRC_IP, indicatorExecuted.alert.host.ip);
		else
			parsed.put(KEY.SRC_IP, "N/A");
		
		//get source port
		if(indicatorExecuted.alert.event_values.urlLocalPort != null)
			parsed.put(KEY.SRC_PORT, indicatorExecuted.alert.event_values.urlLocalPort);
		else if(indicatorExecuted.alert.event_values.netSrcPort != null)
			parsed.put(KEY.SRC_PORT,  indicatorExecuted.alert.event_values.netSrcPort);
		else
			parsed.put(KEY.SRC_PORT, "N/A");
		
		
		//get destination IP
		if(indicatorExecuted.alert.event_values.urlDstIp != null)
			parsed.put(KEY.DST_IP, indicatorExecuted.alert.event_values.urlDstIp);
		else if(indicatorExecuted.alert.event_values.netDstIp != null)
			parsed.put(KEY.DST_IP,  indicatorExecuted.alert.event_values.netDstIp);
		else
			parsed.put(KEY.DST_IP, "N/A");
		
		//get destination port
		if(indicatorExecuted.alert.event_values.urlRemotePort != null)
			parsed.put(KEY.DST_PORT, indicatorExecuted.alert.event_values.urlRemotePort);
		else if(indicatorExecuted.alert.event_values.netDstPort != null)
			parsed.put(KEY.DST_PORT,  indicatorExecuted.alert.event_values.netDstPort);
		else
			parsed.put(KEY.DST_PORT, "N/A");
		
		//get timestamp
		Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.setTime(indicatorExecuted.alert.getEventAt());
        
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
		parsed.put(KEY.OCCURRED, df.format(cal.getTime()));
		
		
		//get product
		parsed.put(KEY.SENSOR, "FireEye-" + indicatorExecuted.product);
		
		//get alert name
		if(indicatorExecuted.alert.name != null)
			parsed.put(KEY.INFECTION_NAME, indicatorExecuted.alert.name);
		else
			parsed.put(KEY.INFECTION_NAME,  "N/A");

		
		//get malicious url
		if(indicatorExecuted.alert.event_values.urlHostname != null) {
			StringBuffer sbUrl = new StringBuffer();
			sbUrl.append(indicatorExecuted.alert.event_values.urlHostname);
			
			if(indicatorExecuted.alert.event_values.urlRequestUrl != null) 
				sbUrl.append(indicatorExecuted.alert.event_values.urlRequestUrl);
	
			//all url
			parsed.put(KEY.CNC_URL, sbUrl.toString());
		}
		else if(indicatorExecuted.alert.event_values.netDstIp != null) {
			StringBuffer sbUrl = new StringBuffer();
			sbUrl.append(indicatorExecuted.alert.event_values.netDstIp);
			
			if(indicatorExecuted.alert.event_values.netDstPort != null);
				sbUrl.append(":" + indicatorExecuted.alert.event_values.netDstPort);
		}
		else {
			parsed.put(KEY.CNC_URL, "N/A");
		}
		
		//get cnc info
		if(indicatorExecuted.alert.event_type != null)
			parsed.put(KEY.CNC_TYPE, indicatorExecuted.alert.event_type);
		else
			parsed.put(KEY.CNC_TYPE, "N/A");
		
		if(indicatorExecuted.alert.source != null)
			parsed.put(KEY.CNC_NAME, indicatorExecuted.alert.source);
		else
			parsed.put(KEY.CNC_NAME, "N/A");
		
		//get list of all source slerts
		List<Map<IndicatorExecuted.ALERT_METADATA,String>> parsedAlerts = parseIndicatorEvents(indicatorExecuted.alert.matched_source_alerts);

		
		if(parsedAlerts != null && parsedAlerts.size() > 0) {
			Map<IndicatorExecuted.ALERT_METADATA,String> firstAlert = parsedAlerts.get(0);
			if(firstAlert != null) {
				//get alert type of indicator
				if(firstAlert.get(IndicatorExecuted.ALERT_METADATA.INDICATOR_NAME) != null)
					parsed.put(KEY.MALWARE_NAME, firstAlert.get(IndicatorExecuted.ALERT_METADATA.INDICATOR_NAME));
				else
					parsed.put(KEY.MALWARE_NAME, "N/A");
				
				//get alert source
				if(firstAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_TYPE) != null)
					parsed.put(KEY.MALWARE_TYPE, firstAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_TYPE));
				else
					parsed.put(KEY.MALWARE_TYPE,  "N/A");
				
				//put url in case it doesnt exist
				if(parsed.get(KEY.ALERT_URL) == null)
					parsed.put(KEY.ALERT_URL, firstAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_URL) );
			}
		}

		//get username if available
		if(indicatorExecuted.alert.event_values.netUsername != null) {
			parsed.put(KEY.USERNAME, indicatorExecuted.alert.event_values.netUsername);
		}
		else if(indicatorExecuted.alert.event_values.urlUsername != null) {
			parsed.put(KEY.USERNAME, indicatorExecuted.alert.event_values.urlUsername);
		}
		
		//get process and path if available
		if(indicatorExecuted.alert.event_values.netProcess != null) {
			parsed.put(KEY.PROCESS, indicatorExecuted.alert.event_values.netProcess);
		}
		else if(indicatorExecuted.alert.event_values.urlProcess != null) {
			parsed.put(KEY.PROCESS,  indicatorExecuted.alert.event_values.netProcess);
		}
		
		if(indicatorExecuted.alert.event_values.netProcessPath != null) {
			parsed.put(KEY.PROCESS_PATH, indicatorExecuted.alert.event_values.netProcessPath);
		}
		else if(indicatorExecuted.alert.event_values.urlProcessPath != null) {
			parsed.put(KEY.PROCESS_PATH, indicatorExecuted.alert.event_values.netProcessPath);
		}
		
		/**
		 * Need to build data filed using event_values then a concat of all source alerts
		 */
		StringBuffer sbEventData = new StringBuffer();
		
		//get data headers
		if(indicatorExecuted.alert.event_values.urlHttpHeader != null) {
			sbEventData.append(indicatorExecuted.alert.event_values.urlHttpHeader);
			sbEventData.append("\n");
		}

		for(Map<IndicatorExecuted.ALERT_METADATA,String> parsedAlert : parsedAlerts) {
			sbEventData.append("Alert URL: " + parsedAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_URL) + "\n");
			sbEventData.append("Timestamp: " + parsedAlert.get(IndicatorExecuted.ALERT_METADATA.TIMESTAMP) + "\n");
			sbEventData.append("Type: " + parsedAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_TYPE) + "\n");
			sbEventData.append("Dst IP: " + parsedAlert.get(IndicatorExecuted.ALERT_METADATA.DST_IP) + "\n");
			sbEventData.append("\n");
		}
				
		parsed.put(KEY.CNC_DATA, sbEventData.toString());
		
		return(parsed);
	}
	
	
	private Map<KEY,String> parseJsonExploitBlocked(String json) throws Exception {
		Map<KEY,String> parsed = new HashMap<>();
		
		Gson gson = new GsonBuilder().setDateFormat(dateMatch).create();
		
		ExploitBlocked exploitBlocked = gson.fromJson(json, ExploitBlocked.class);
		
		//verify json parsed
		if(exploitBlocked == null)
			throw new Exception("Parsed JSON is null");
		
		//verify alert available
		if(exploitBlocked.alert == null)
			throw new Exception("No alert object");
	
		//verify event_values available
		if(exploitBlocked.alert.event_values == null)
			throw new Exception("No event values");
		
		//verify analysis_details
		if(exploitBlocked.alert.event_values.analysis_details == null)
			throw new Exception("No analysis_details");
	
		
		//get timestamp
		Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.setTime(exploitBlocked.alert.getEventAt());
        
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
		parsed.put(KEY.OCCURRED, df.format(cal.getTime()));
		
		
		//get source IP
		if(exploitBlocked.alert.host.ip != null)
			parsed.put(KEY.SRC_IP, exploitBlocked.alert.host.ip);
		else
			parsed.put(KEY.SRC_IP, "N/A");
		
		//get product
		parsed.put(KEY.SENSOR, "FireEye-" + exploitBlocked.product);
		
		//get alert name
		if(exploitBlocked.alert.name != null)
			parsed.put(KEY.INFECTION_NAME, exploitBlocked.alert.name);
		else
			parsed.put(KEY.INFECTION_NAME,  "N/A");

		
		//set CNC 
		//parsed.put(KEY.CNC_URL, "N/A");
		//parsed.put(KEY.CNC_NAME, "N/A");
		

		
		
		/**
		 * Need to build data filed using analysis_detail then a concat of all data
		 */
		StringBuffer sbAnalysisData = new StringBuffer();
		
		//parse analysis_details
		List<AnalysisDetail> analysisDetails = exploitBlocked.alert.event_values.analysis_details;
		
		
		for(AnalysisDetail analysisDetail : analysisDetails) {
			if(analysisDetail != null && analysisDetail.detail_type != null) {
				//   action, analysis, analysis_result, apicall, EXPLOITED_PROCESS,
				//   file, folder, network, officevbamacrodetection, os, OS-CORRELATION
				//   process, regkey
				switch(analysisDetail.detail_type) {
					case "action":
						if(analysisDetail.action != null) {
							StringBuffer sbAction = new StringBuffer();
						
							if(analysisDetail.action.mode != null) {
								sbAction.append(analysisDetail.action.mode);
								
								if( (analysisDetail.action.result != null) && (! analysisDetail.action.result.isEmpty()) )  {
									sbAction.append(": " + analysisDetail.action.result);
								}
								
								parsed.put(KEY.ACTION, sbAction.toString());
							}
						}
						
						break;
						
					case "analysis":
						if(analysisDetail.analysis != null) {
							if(analysisDetail.analysis.mode != null) {
								parsed.put(KEY.MALWARE_NAME, analysisDetail.analysis.mode);
							}
							
							if(analysisDetail.analysis.ftype != null) {
								parsed.put(KEY.MALWARE_TYPE, analysisDetail.analysis.ftype);
							}
						}
						break;
						
					case "analysis_result":
						StringBuffer sbAnalysisResult = new StringBuffer();
						
						if(analysisDetail.analysis_result != null) {
							if(analysisDetail.analysis_result.is_malicious != null) {
								sbAnalysisResult.append("Malicious: " + analysisDetail.analysis_result.is_malicious);
							}
							if(analysisDetail.analysis_result.is_blocked != null) {
								sbAnalysisResult.append("  Blocked: " + analysisDetail.analysis_result.is_blocked);
							}
							if(analysisDetail.analysis_result._CONTENTS != null) {
								sbAnalysisResult.append("  Contents: " + analysisDetail.analysis_result._CONTENTS);
							}
						}
						
						break;
						
					case "apicall":
						//not using yet
						break;
						
					case "EXPLOITED_PROCESS":
						//not using yet
						break;
						
					case "file":
						if(analysisDetail.file != null) {
							sbAnalysisData.append("File\n");
							sbAnalysisData.append("Path: " + analysisDetail.file.value + "\n");
							sbAnalysisData.append("Size: " + analysisDetail.file.filesize + "\n");
							sbAnalysisData.append("Type: " + analysisDetail.file.type + "\n");
							sbAnalysisData.append("Potential Exploit: " + analysisDetail.file.potential_exploit_document + "\n");
							sbAnalysisData.append("MD5: " + analysisDetail.file.md5sum + "\n");
							sbAnalysisData.append("SHA1: " + analysisDetail.file.sha1sum + "\n");
							sbAnalysisData.append("\n");
						}
						
						break;
						
					case "folder":
						//not using yet
						break;
						
					case "network":
						if(analysisDetail.network != null) {
							if(analysisDetail.network.ipaddress != null) {
								parsed.put(KEY.DST_IP, analysisDetail.network.ipaddress); 
							}
							
							if(analysisDetail.network.destination_port != null) {
								parsed.put(KEY.DST_PORT, analysisDetail.network.destination_port); 
							}
						}
						
						break;
						
					case "officevbamacrodetection":
						//not using yet
						break;
						
					case "os":
						//not using yet
						break;
						
					case "OS-CORRECLATION":
						//not using yet
						break;
						
					case "process":
						if(analysisDetail.process != null) {
							//try cmdline first since it contains more details
							if( (analysisDetail.process.cmdline) != null && (! analysisDetail.process.cmdline.isEmpty()) ) {
								parsed.put(KEY.PROCESS, analysisDetail.process.cmdline);
							}
							else if( (analysisDetail.process.value) != null && (! analysisDetail.process.value.isEmpty()) ) {
								parsed.put(KEY.PROCESS, analysisDetail.process.value);
							}
						}
						
						break;
						
					case "regkey":
						if(analysisDetail.regkey != null) {
							sbAnalysisData.append("Registry Key\n");
							sbAnalysisData.append("Key Path: " + analysisDetail.regkey.value + "\n");
							sbAnalysisData.append("Value Name: " + analysisDetail.regkey.valueName + "\n");
							sbAnalysisData.append("Value Text: " + analysisDetail.regkey.valueText + "\n");
							sbAnalysisData.append("Value Type: " + analysisDetail.regkey.valueType + "\n");
							sbAnalysisData.append("Value Mode: " + analysisDetail.regkey.mode + "\n");
							sbAnalysisData.append("\n");
						}
						
						break;
					
					default:
						System.out.println("Unknown analysis detail type: " + analysisDetail.detail_type);
				}
					
			}
		}

		//set default in case analysis details don't include
		if(parsed.get(KEY.SRC_PORT) == null)
			parsed.put(KEY.SRC_PORT,"N/A");
		if(parsed.get(KEY.PROCESS) == null )
			parsed.put(KEY.PROCESS, "N/A");
		if(parsed.get(KEY.DST_IP) == null)
				parsed.put(KEY.DST_IP, "N/A");
		if(parsed.get(KEY.DST_PORT)== null)
			parsed.put(KEY.DST_PORT, "N/A");
		//if(parsed.get(KEY.MALWARE_NAME) == null)
		//	parsed.put(KEY.MALWARE_NAME, "N/A");
		//if(parsed.get(KEY.MALWARE_TYPE) == null)
		//	parsed.put(KEY.MALWARE_TYPE, "N/A");
		if(parsed.get(KEY.ALERT_URL) == null)
			parsed.put(KEY.ALERT_URL, "N/A"); //firstAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_URL) );
		if(parsed.get(KEY.USERNAME) == null)
			parsed.put(KEY.USERNAME, "N/A");
		if(parsed.get(KEY.PROCESS) == null)
			parsed.put(KEY.PROCESS, "N/A");
		if(parsed.get(KEY.PROCESS_PATH) == null)
			parsed.put(KEY.PROCESS_PATH, "N/A");
				
		parsed.put(KEY.CNC_DATA, sbAnalysisData.toString());

		return(parsed);
	}
	
	
	private Map<KEY,String> parseJsonMalwareObject(String json) throws Exception {
		Map<KEY,String> parsed = new HashMap<>();
		
		Gson gson = new GsonBuilder().setDateFormat(dateMatch).create();
		
		MalwareObject malwareObject = gson.fromJson(json, MalwareObject.class);
		
		//verify json parsed
		if(malwareObject == null)
			throw new Exception("Parsed JSON is null");
		
		//verify alert available
		if(malwareObject.alert == null)
			throw new Exception("No alert object");
	
		//verify event_values available
		//Remove check since NX can also alert on network objects
		//if(malwareObject.alert.event_values == null)
		//	throw new Exception("No event values");
		
		//get source IP
		if(malwareObject.alert.host != null && malwareObject.alert.host.ip != null)
			parsed.put(KEY.SRC_IP, malwareObject.alert.host.ip);
		else if(malwareObject.alert.src != null && malwareObject.alert.src.ip != null)
			parsed.put(KEY.SRC_IP,  malwareObject.alert.src.ip);
		else
			parsed.put(KEY.SRC_IP, "N/A");
		
		//get agent ID
		if(malwareObject.alert.host != null && malwareObject.alert.host.agent_id != null)
			parsed.put(KEY.AGENT_ID, malwareObject.alert.host.agent_id);
		//dont add an "N/A" agent id or HX will try to parse as an actual id
		//else
		//	parsed.put(KEY.AGENT_ID, "N/A");
		
		//get source port
		if(malwareObject.alert.src != null && malwareObject.alert.src.port != null)
			parsed.put(KEY.SRC_PORT, malwareObject.alert.src.port);
		else
			parsed.put(KEY.SRC_PORT, "N/A");
		
		
		//get destination IP
		if(malwareObject.alert.dst != null && malwareObject.alert.dst.ip != null)
			parsed.put(KEY.DST_IP, malwareObject.alert.dst.ip);
		else
			parsed.put(KEY.DST_IP, "N/A");
		
		//get destination port
		if(malwareObject.alert.dst != null && malwareObject.alert.dst.port != null)
			parsed.put(KEY.DST_PORT, malwareObject.alert.dst.port);
		else
			parsed.put(KEY.DST_PORT, "N/A");
		
		//get timestamp
		Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.setTime(malwareObject.alert.getOccurred());
        
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
		parsed.put(KEY.OCCURRED, df.format(cal.getTime()));
		
		
		//get product
		parsed.put(KEY.SENSOR, "FireEye-" + malwareObject.product);
		
		//get alert name
		if(malwareObject.alert.name != null)
			parsed.put(KEY.INFECTION_NAME, malwareObject.alert.name);
		else
			parsed.put(KEY.INFECTION_NAME,  "N/A");

		
		//get malicious url
		parsed.put(KEY.CNC_URL, "N/A");
		
		//get cnc info
		parsed.put(KEY.CNC_NAME, "N/A");
		
		//get list of all HX source alerts, will parse NX alerts later since they are simplified
		List<Map<MalwareObject.ALERT_METADATA,String>> detections = null;
		if(malwareObject.alert.event_values != null && malwareObject.alert.event_values.detections != null && 
				malwareObject.alert.event_values.detections.detection != null) {
			detections = parseMalwareDetections(malwareObject.alert.event_values.detections.detection);
		}

				
		/**
		 * Need to build data filed using detections then a concat of all source alerts
		 */
		StringBuffer sbMalwareData = null;
		
		//Parse the HX related alerts
		if(detections != null && detections.size() > 0) {
			sbMalwareData = new StringBuffer();
			
			for(Map<MalwareObject.ALERT_METADATA,String> detection : detections) {
				sbMalwareData.append("Object Type: " + detection.get(MalwareObject.ALERT_METADATA.OBJECT_TYPE) + "\n");
				sbMalwareData.append("File Path: " + detection.get(MalwareObject.ALERT_METADATA.FILE_PATH) + "\n");
				sbMalwareData.append("Modification Time: " + detection.get(MalwareObject.ALERT_METADATA.MODIFICATION_TIME) + "\n");
				sbMalwareData.append("MD5Sum: " + detection.get(MalwareObject.ALERT_METADATA.MD5SUM) + "\n");
				sbMalwareData.append("Infection Name: " + detection.get(MalwareObject.ALERT_METADATA.INFECTION_NAME) + "\n");
				sbMalwareData.append("Infection Type: " + detection.get(MalwareObject.ALERT_METADATA.INFECTION_TYPE) + "\n");
				sbMalwareData.append("Applied Action: " + detection.get(MalwareObject.ALERT_METADATA.APPLIED_ACTION) + "\n");
				sbMalwareData.append("Access Time: " + detection.get(MalwareObject.ALERT_METADATA.TIMESTAMP) + "\n");
				sbMalwareData.append("\n");
			

				//search on VirusTotal if MD5 available
				if(detection.get(MalwareObject.ALERT_METADATA.MD5SUM) != null) {
					try {
						VirusTotal vt = new VirusTotal();
						vtFile = vt.search(detection.get(MalwareObject.ALERT_METADATA.MD5SUM));
					}
					catch(FileNotFoundException fnfe) {
						sbMalwareData.append("VirusTotal: No hits for hash " + detection.get(MalwareObject.ALERT_METADATA.MD5SUM) + "\n");
					}
					catch(Exception e) {
						sbMalwareData.append("VirusTotal: Error " + e.getMessage() + "\n");
					}
				}

			}
			parsed.put(KEY.MALWARE_DATA, sbMalwareData.toString());
		}
		//or try NX source alerts
		else if( (malwareObject.alert.explanation != null) && (malwareObject.alert.explanation.malwaredetected != null) &&
			(malwareObject.alert.explanation.malwaredetected.malware != null) ) {
				
			//put http_post data in CNC_DATA field
			if(malwareObject.alert.explanation.malwaredetected.malware != null & malwareObject.alert.explanation.malwaredetected.malware.http_header != null) {
				parsed.put(KEY.CNC_DATA, malwareObject.alert.explanation.malwaredetected.malware.http_header);
			}
			
			//get hostname for CNC_URL
			if(malwareObject.alert.src != null && malwareObject.alert.src.host != null) {
				parsed.put(KEY.CNC_URL, malwareObject.alert.src.host);
			}
			parsed.put(KEY.CNC_URL, null);
				
			sbMalwareData = new StringBuffer();
			
			//Malware name
			if(malwareObject.alert.explanation.malwaredetected.malware.name != null) {
				sbMalwareData.append("Malware Name: " + malwareObject.alert.explanation.malwaredetected.malware.name + "\n");
			}
			else {
				sbMalwareData.append("Malware Name: N/A\n");
			}
			
			//Source type
			if(malwareObject.alert.explanation.malwaredetected.malware.stype != null) {
				sbMalwareData.append("Malware Detection Type: " + malwareObject.alert.explanation.malwaredetected.malware.stype + "\n");
			}
			else {
				sbMalwareData.append("Malware Detection Type: N/A\n");
			}
			
			//Execution time
			if(malwareObject.alert.explanation.malwaredetected.malware.executed_at != null) {
				sbMalwareData.append("Execution Time: " + malwareObject.alert.explanation.malwaredetected.malware.executed_at + "\n");
			}
			else {
				sbMalwareData.append("Execution Time: N/A");
			}
					
			//MD5 hash
			if(malwareObject.alert.explanation.malwaredetected.malware.md5sum != null) {
				sbMalwareData.append("MD5Sum: " + malwareObject.alert.explanation.malwaredetected.malware.md5sum +"\n");
			}
			else {
				sbMalwareData.append("MD5Sum: N/A\n");
			}
		
			
			//Source IP
			if(malwareObject.alert.src != null && malwareObject.alert.src.ip != null) {
				sbMalwareData.append("Source IP: " + malwareObject.alert.src.ip +"\n");
			}
			
			//Destination IP
			if(malwareObject.alert.dst != null && malwareObject.alert.dst.ip != null) {
				sbMalwareData.append("Destination IP: " + malwareObject.alert.dst.ip +"\n");
			}
			
			//Destination Port
			if(malwareObject.alert.dst != null && malwareObject.alert.dst.port != null) {
				sbMalwareData.append("Destination Port: " + malwareObject.alert.dst.port +"\n");
			}
			
			parsed.put(KEY.MALWARE_DATA, sbMalwareData.toString());
		}
		
		return(parsed);
	}
	
	
	private Map<KEY,String> parseJsonIndicatorPresence(String json) throws Exception {
		Map<KEY,String> parsed = new HashMap<>();
		
		Gson gson = new GsonBuilder().setDateFormat(dateMatch).create();
		
		IndicatorPresence indicatorPresence = gson.fromJson(json, IndicatorPresence.class);
		
		//verify json parsed
		if(indicatorPresence == null)
			throw new Exception("Parsed JSON is null");
		
		//verify alert available
		if(indicatorPresence.alert == null)
			throw new Exception("No alert object");
		
		//verify event_values available
		if(indicatorPresence.alert.event_values == null)
			throw new Exception("No event values");
		
		parsed.put(KEY.SRC_IP, indicatorPresence.alert.host.ip);
		parsed.put(KEY.SRC_PORT, "N/A");
		parsed.put(KEY.DST_IP, "N/A");
		parsed.put(KEY.DST_PORT, "N/A");
		
		//get timestamp
		Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.setTime(indicatorPresence.alert.getEventAt());
        
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
		parsed.put(KEY.OCCURRED, df.format(cal.getTime()));
		
		
		//get product
		parsed.put(KEY.SENSOR, "FireEye-" + indicatorPresence.product);
		
		//get alert name
		if(indicatorPresence.alert.name != null)
			parsed.put(KEY.INFECTION_NAME, indicatorPresence.alert.name);
		else
			parsed.put(KEY.INFECTION_NAME,  "N/A");

		
		parsed.put(KEY.CNC_URL, "N/A");
		
		//get cnc info
		if(indicatorPresence.alert.event_type != null)
			parsed.put(KEY.CNC_TYPE, indicatorPresence.alert.event_type);
		else
			parsed.put(KEY.CNC_TYPE, "N/A");
		
		if(indicatorPresence.alert.source != null)
			parsed.put(KEY.CNC_NAME, indicatorPresence.alert.source);
		else
			parsed.put(KEY.CNC_NAME, "N/A");
		
		//get list of all source alerts
/**
 		List<Map<IndicatorExecuted.ALERT_METADATA,String>> parsedAlerts = parseIndicatorEvents(indicatorPresence.alert.matched_source_alerts);


		
		if(parsedAlerts != null && parsedAlerts.size() > 0) {
			Map<IndicatorExecuted.ALERT_METADATA,String> firstAlert = parsedAlerts.get(0);
			if(firstAlert != null) {
				//get alert type of indicator
				if(firstAlert.get(IndicatorExecuted.ALERT_METADATA.INDICATOR_NAME) != null)
					parsed.put(KEY.MALWARE_NAME, firstAlert.get(IndicatorExecuted.ALERT_METADATA.INDICATOR_NAME));
				else
					parsed.put(KEY.MALWARE_NAME, "N/A");
				
				//get alert source
				if(firstAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_TYPE) != null)
					parsed.put(KEY.MALWARE_TYPE, firstAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_TYPE));
				else
					parsed.put(KEY.MALWARE_TYPE,  "N/A");
				
				//put url in case it doesnt exist
				if(parsed.get(KEY.ALERT_URL) == null)
					parsed.put(KEY.ALERT_URL, firstAlert.get(IndicatorExecuted.ALERT_METADATA.ALERT_URL) );
			}
		}
**/
		
		//get username if available
		if(indicatorPresence.alert.event_values.fileUsername != null) {
			parsed.put(KEY.USERNAME, indicatorPresence.alert.event_values.fileUsername);
		}
		else {
			System.err.println("Cannot extract USERNAME");
		}
		
		//get process and path if available
		if(indicatorPresence.alert.event_values.fileProcess != null) {
			parsed.put(KEY.PROCESS, indicatorPresence.alert.event_values.fileProcess);
		}
		else {
			System.err.println("Cannot extract PROCESS");
		}
		
		
		if(indicatorPresence.alert.event_values.fileProcessPath != null) {
			parsed.put(KEY.PROCESS_PATH, indicatorPresence.alert.event_values.fileProcessPath);
		}
		else {
			System.err.println("Cannot extract PROCESS_PATH");
		}
		
		return(parsed);
	}
	
	
	private List<Map<IndicatorExecuted.ALERT_METADATA,String>> parseIndicatorEvents(List<IndicatorExecuted.Alert.MatchedSourceAlerts> sourceAlerts) {
		List<Map<IndicatorExecuted.ALERT_METADATA,String>> parsedAlerts = new ArrayList<Map<IndicatorExecuted.ALERT_METADATA,String>>();
		
		//if source alerts null or empty just return empty list
		if(sourceAlerts == null || sourceAlerts.size() == 0)
			return(parsedAlerts);
		
		for(IndicatorExecuted.Alert.MatchedSourceAlerts sourceAlert : sourceAlerts) {
			Map<IndicatorExecuted.ALERT_METADATA,String> parsed = new HashMap<>();

			
			//alert url
			if(sourceAlert.url != null)
				parsed.put(IndicatorExecuted.ALERT_METADATA.ALERT_URL, sourceAlert.url);
			else
				parsed.put(IndicatorExecuted.ALERT_METADATA.ALERT_URL, "N/A");
			
			//product name
			if(sourceAlert.meta.product_name != null)
				parsed.put(IndicatorExecuted.ALERT_METADATA.PRODUCT, sourceAlert.meta.product_name);
			else
				parsed.put(IndicatorExecuted.ALERT_METADATA.PRODUCT, "N/A");
			
			//alert type
			if(sourceAlert.meta.alert_type != null)
				parsed.put(IndicatorExecuted.ALERT_METADATA.ALERT_TYPE, sourceAlert.meta.alert_type);
			else
				parsed.put(IndicatorExecuted.ALERT_METADATA.ALERT_TYPE, "N/A");
			
			//dst ip
			if(sourceAlert.meta.dst_ip != null)
				parsed.put(IndicatorExecuted.ALERT_METADATA.DST_IP, sourceAlert.meta.dst_ip);
			else
				parsed.put(IndicatorExecuted.ALERT_METADATA.DST_IP, "N/A");
					
			//alert severity
			if(sourceAlert.meta.alert_severity != null)
				parsed.put(IndicatorExecuted.ALERT_METADATA.ALERT_SEVERITY, sourceAlert.meta.alert_severity);
			else
				parsed.put(IndicatorExecuted.ALERT_METADATA.ALERT_SEVERITY, "N/A");
						
			//src ip
			if(sourceAlert.meta.src_ip != null)
				parsed.put(IndicatorExecuted.ALERT_METADATA.SRC_IP, sourceAlert.meta.src_ip);
			else
				parsed.put(IndicatorExecuted.ALERT_METADATA.SRC_IP, "N/A");
			
			//indicator name
			if(sourceAlert.indicator_name != null)
				parsed.put(IndicatorExecuted.ALERT_METADATA.INDICATOR_NAME, sourceAlert.indicator_name);
			else
				parsed.put(IndicatorExecuted.ALERT_METADATA.INDICATOR_NAME, "N/A");
					
			//timestamp
			Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
	        cal.setTime(sourceAlert.meta.getTimestamp());
	        
			parsed.put(IndicatorExecuted.ALERT_METADATA.TIMESTAMP, df.format(cal.getTime()));
			
			//add the created map to the list
			parsedAlerts.add(parsed);
		}
		
		
		return(parsedAlerts);
	}
	
	
	private List<Map<MalwareObject.ALERT_METADATA,String>> parseMalwareDetections(List<MalwareObject.Alert.Event.Detection> detections) {
		List<Map<MalwareObject.ALERT_METADATA,String>> parsedAlerts = new ArrayList<Map<MalwareObject.ALERT_METADATA,String>>();
		
		//if source alerts null or empty just return empty list
		if(detections == null || detections.size() == 0)
			return(parsedAlerts);
		
		for(MalwareObject.Alert.Event.Detection detection : detections) {
			Map<MalwareObject.ALERT_METADATA,String> parsed = new HashMap<>();

			
			//product name
			if(detection.infected_object != null && detection.infected_object.object_type != null)
				parsed.put(MalwareObject.ALERT_METADATA.OBJECT_TYPE, detection.infected_object.object_type);
			else
				parsed.put(MalwareObject.ALERT_METADATA.OBJECT_TYPE, "N/A");
			
			
			//file path
			if(detection.infected_object != null && 
					detection.infected_object.file_object != null &&
					detection.infected_object.file_object != null &
					detection.infected_object.file_object.file_path != null )
				parsed.put(MalwareObject.ALERT_METADATA.FILE_PATH, detection.infected_object.file_object.file_path);
			else
				parsed.put(MalwareObject.ALERT_METADATA.FILE_PATH, "N/A");
			
			
			//modification time
			if(detection.infected_object != null && 
					detection.infected_object.file_object != null &&
					detection.infected_object.file_object != null &
					detection.infected_object.file_object.modification_time != null )
				parsed.put(MalwareObject.ALERT_METADATA.MODIFICATION_TIME, detection.infected_object.file_object.modification_time);
			else
				parsed.put(MalwareObject.ALERT_METADATA.MODIFICATION_TIME, "N/A");
			
			
			//MD5Sum
			if(detection.infected_object != null && 
					detection.infected_object.file_object != null &&
					detection.infected_object.file_object != null &
					detection.infected_object.file_object.md5sum != null )
				parsed.put(MalwareObject.ALERT_METADATA.MD5SUM, detection.infected_object.file_object.md5sum);
			else
				parsed.put(MalwareObject.ALERT_METADATA.MD5SUM, "N/A");
			
			
			//indication name
			if(detection.infection != null && detection.infection.infection_name != null)
				parsed.put(MalwareObject.ALERT_METADATA.INFECTION_NAME, detection.infection.infection_name);
			else
				parsed.put(MalwareObject.ALERT_METADATA.INFECTION_NAME, "N/A");
			
			
			//indication type
			if(detection.infection != null && detection.infection.infection_type != null)
				parsed.put(MalwareObject.ALERT_METADATA.INFECTION_TYPE, detection.infection.infection_type);
			else
				parsed.put(MalwareObject.ALERT_METADATA.INFECTION_TYPE, "N/A");
			
			
			//applied action
			if(detection.action != null && detection.action.applied_action != null)
				parsed.put(MalwareObject.ALERT_METADATA.APPLIED_ACTION, detection.action.applied_action);
			else
				parsed.put(MalwareObject.ALERT_METADATA.APPLIED_ACTION, "N/A");
			

					
			//timestamp
			if(detection.infected_object != null && 
					detection.infected_object.file_object != null &&
					detection.infected_object.file_object != null &
					detection.infected_object.file_object.access_time != null ) {
				Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
		        cal.setTime(Common.parseDates(detection.infected_object.file_object.access_time));
		        
				parsed.put(MalwareObject.ALERT_METADATA.TIMESTAMP, df.format(cal.getTime()));
				//Date accessTime = Common.parseDates(detection.infected_object.file_object.access_time);
				//parsed.put(MalwareObject.ALERT_METADATA.TIMESTAMP, df.format(accessTime));
			}
			else {
				parsed.put(MalwareObject.ALERT_METADATA.MD5SUM, "N/A");
			}
			
			//add the created map to the list
			parsedAlerts.add(parsed);
		}
		
		
		return(parsedAlerts);
	}
	
	
	private Map<KEY,String> parseJsonInfectionMatch(String json) throws Exception {
		Map<KEY,String> parsed = new HashMap<>();

		Gson gson = new GsonBuilder().setDateFormat(dateMatch).create();
	
		InfectionMatch infectionMatch = gson.fromJson(json, InfectionMatch.class);
		
		//verify json parsed
		if(infectionMatch == null) {
			System.out.println("infectionMatch is null");
			throw new Exception("Parsed JSON is null");
		}	
		//verify alert available
		if(infectionMatch.alert == null) {
			System.out.println("infectionMatch.alert is null");
			throw new Exception("No alert object");
		}
	
		//get source IP
		if( (infectionMatch.alert.src != null) || (infectionMatch.alert.src.ip != null) )
			parsed.put(KEY.SRC_IP, infectionMatch.alert.src.ip);
		else
			parsed.put(KEY.SRC_IP, "N/A");
		
		//get source port
		if( (infectionMatch.alert.src != null) || (infectionMatch.alert.src.port != null) )
			parsed.put(KEY.SRC_PORT, infectionMatch.alert.src.port);
		else
			parsed.put(KEY.SRC_PORT, "N/A");
		
		//get src hostname 
		if( (infectionMatch.alert.src != null) || (infectionMatch.alert.src.host != null) ) {
			parsed.put(KEY.SRC_HOST, infectionMatch.alert.src.host);
		}
		else {
			parsed.put(KEY.SRC_HOST, "N/A");
		}

		//get dest IP
		if( (infectionMatch.alert.dst != null) && (infectionMatch.alert.dst.ip != null) )
			parsed.put(KEY.DST_IP, infectionMatch.alert.dst.ip);
		else
			parsed.put(KEY.DST_IP, "N/A");
		
		//get dest port
		if( (infectionMatch.alert.dst != null) && (infectionMatch.alert.dst.port != null) )
			parsed.put(KEY.DST_PORT, infectionMatch.alert.dst.port);
		else
			parsed.put(KEY.DST_PORT, "N/A");
	
		//get dest hostname 
		if( (infectionMatch.alert.dst != null) || (infectionMatch.alert.dst.host != null) ) {
			parsed.put(KEY.DST_HOST, infectionMatch.alert.dst.host);
		}
		else {
			parsed.put(KEY.DST_HOST, "N/A");
		}
		
		//get infection type
		if(infectionMatch.alert.name != null)
			parsed.put(KEY.INFECTION_NAME, infectionMatch.alert.name);
		else
			parsed.put(KEY.INFECTION_NAME, "N/A");
		
		//get malware name and type
		if( (infectionMatch.alert.explanation != null) && (infectionMatch.alert.explanation.malwaredetected != null) &&
			(infectionMatch.alert.explanation.malwaredetected.malware != null) ) {
			if(infectionMatch.alert.explanation.malwaredetected.malware.name != null) {
				parsed.put(KEY.MALWARE_NAME, infectionMatch.alert.explanation.malwaredetected.malware.name);
			}
			else {
				parsed.put(KEY.MALWARE_NAME, "N/A");
			}
			if(infectionMatch.alert.explanation.malwaredetected.malware.stype != null) {
				parsed.put(KEY.MALWARE_TYPE, infectionMatch.alert.explanation.malwaredetected.malware.stype);
			}
			else {
				parsed.put(KEY.MALWARE_TYPE, "N/A");
			}

		}
		
		//get CNC
		if( (infectionMatch.alert.explanation != null) && (infectionMatch.alert.explanation.cncservices != null) &&
			(infectionMatch.alert.explanation.cncservices.cncservice != null) ) {
			if(infectionMatch.alert.explanation.cncservices.cncservice.sname != null) {
				parsed.put(KEY.CNC_NAME, infectionMatch.alert.explanation.cncservices.cncservice.sname);
			}
			else {
				parsed.put(KEY.CNC_NAME, "N/A");
			}
			if(infectionMatch.alert.explanation.cncservices.cncservice.url != null) {
				parsed.put(KEY.CNC_URL, infectionMatch.alert.explanation.cncservices.cncservice.url);
			}
			else {
				parsed.put(KEY.CNC_URL, "N/A");
			}
			if(infectionMatch.alert.explanation.cncservices.cncservice.type != null) {
				parsed.put(KEY.CNC_TYPE, infectionMatch.alert.explanation.cncservices.cncservice.type);
			}
			else {
				parsed.put(KEY.CNC_TYPE, "N/A");
			}
			if(infectionMatch.alert.explanation.cncservices.cncservice.channel != null) {
				parsed.put(KEY.CNC_DATA, infectionMatch.alert.explanation.cncservices.cncservice.channel);
			}
			else {
				parsed.put(KEY.CNC_DATA, "N/A");
			}
		}
	
		//get alert url
		if(infectionMatch.alert.alerturl != null)
			parsed.put(KEY.ALERT_URL, infectionMatch.alert.alerturl);
		else
			parsed.put(KEY.ALERT_URL, "N/A");
		
		//get alert date or set to Now
		if(infectionMatch.alert.getOccurred() != null) {
			Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
			cal.setTime(infectionMatch.alert.getOccurred());
        
			df.setTimeZone(TimeZone.getTimeZone("UTC"));
			parsed.put(KEY.OCCURRED, df.format(cal.getTime()));
			//parsed.put(KEY.OCCURRED, df.format(infectionMatch.alert.getOccurred()) );
		}
		else {
			parsed.put(KEY.OCCURRED, "N/A");
		}
		
		//get alert sensor name
		if(infectionMatch.alert.sensor != null)
			parsed.put(KEY.SENSOR, infectionMatch.alert.sensor);

		return(parsed);
	}
}
