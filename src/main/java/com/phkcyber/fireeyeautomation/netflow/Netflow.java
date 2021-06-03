package com.phkcyber.fireeyeautomation.netflow;

import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.Locale;

import com.google.gson.Gson;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;

import com.phkcyber.fireeyeautomation.logformat.LogEntry;
import com.phkcyber.fireeyeautomation.net.SilkSearch;

public class Netflow {
	private SimpleDateFormat dfIn = new SimpleDateFormat("MM/dd/yyyy");
	private SimpleDateFormat dfNetflow = new SimpleDateFormat("yyyy/MM/dd");
        private SimpleDateFormat dfDateTime = new SimpleDateFormat("yyyy'-'MM'-'dd HH:mm:ss", Locale.US);

	private int MAX_LOGS_RETURN=500;
	
	public Netflow() {
		
	}

	public String searchToJson(String strDateStart, String strDateEnd, String cidr, int maxLogs) throws Exception {
		SilkSearch silkSearch = new SilkSearch();
		
		//parse the start date
		Calendar calStart = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		try {
			calStart.setTime( dfIn.parse(strDateStart) );
		}
		catch(Exception e) {
			throw new Exception(e);
		}
		
		//parse the end date
		Calendar calEnd = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		try {
			calEnd.setTime( dfIn.parse(strDateEnd) );
		}
		catch(Exception e) {
			throw new Exception(e);
		}
		
		//search netflow logs
		List<LogEntry> logs = silkSearch.search(calStart, calEnd, cidr, maxLogs);
		
		System.out.println("Logs retrieved: " + logs.size());
		//convert logs to json
		Gson gson = new Gson();
		return(gson.toJson( parseLogs(logs) ) );
	}
	
	public List<Map<String,Object>> searchFireEyeAlert(String strDate, String srcCidr, String dstCidr) throws Exception {
		SilkSearch silkSearch = new SilkSearch();
		
		//parse the start date
		Calendar calSearch = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		try {
			calSearch.setTime( dfDateTime.parse(strDate) );
		}
		catch(Exception e) {
			throw new Exception(e);
		}
				
		//search netflow logs
		List<LogEntry> logs = silkSearch.search(calSearch, srcCidr, dstCidr, MAX_LOGS_RETURN);
		
		System.out.println("Logs retrieved: " + logs.size());

		return(parseLogs(logs));
	}
	
	private List<Map<String,Object>> parseLogs(List<LogEntry> logs) {
		List<Map<String,Object>> retLogs = new ArrayList<>();
		
		for(LogEntry log : logs) {
			Map<String,Object> entry = new HashMap<>();
			
			entry.put("src", log.getSrc());
			entry.put("sport", log.getSrcPort());
			entry.put("dst", log.getDst());
			entry.put("dport", log.getDstPort());
			entry.put("bytes", log.getSent());
			entry.put("proto", log.getProto());

			entry.put("duration", log.getDuration());
			entry.put("application", log.getApplication());

			if(log.getUser() != null)
				entry.put("user", log.getUser());
			else
				entry.put("user", "");

			if(log.getDateTime() != null)
				entry.put("timestamp", dfDateTime.format(log.getDateTime()));

			if(log.getDstCountry() != null)
				entry.put("dst_country", log.getDstCountry().toUpperCase());
			else
				entry.put("dst_country", "");

			entry.put("duration", log.getDuration());
			
			retLogs.add(entry);
		}
		return(retLogs);
	}
	
	public List<LogEntry> search(String startDate, String endDate, String cidr) throws Exception {
		List<LogEntry> logs = new ArrayList<>();
		
		
		return(logs);
	}
	
}
