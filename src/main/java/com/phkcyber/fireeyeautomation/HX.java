package com.phkcyber.fireeyeautomation;

import java.io.BufferedReader;

import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import java.util.*;

import java.util.logging.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import com.phkcyber.fireeyeautomation.pojo.UpdateHostSetResponse;
import com.phkcyber.fireeyeautomation.pojo.Host;
import com.phkcyber.fireeyeautomation.pojo.HostAlert;
import com.phkcyber.fireeyeautomation.pojo.HostResponse;
import com.phkcyber.fireeyeautomation.pojo.HostSearch;
import com.phkcyber.fireeyeautomation.pojo.HostSet;
import com.phkcyber.fireeyeautomation.pojo.UpdateHostSet;
import com.phkcyber.fireeyeautomation.net.CustomSocketFactory;

import org.apache.commons.codec.binary.Base64;


public class HX {
	private Logger logger;
	
	private String hxip="";
	private String hxport="";
	private String hxuser="";
	private String hxpass="";
	private String token=null;
	private String malwareHostsetId="1098";
	private String malwareHostsetName="Malware_Turned_On";

	
	public HX() {
		logger = Logger.getLogger("HX");
		logger.setLevel(Level.FINE);
	}
	
	public void login() throws Exception {
		String url = getHostUrl() + "/hx/api/v3/token";
		
		Map<String,String> requestHeaders = new HashMap<>();
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("Authorization", generateAuth());
		Map<String,String> responseHeaders = new HashMap<>();
		responseHeaders.put("X-FeApi-Token", null);
		
		logger.log(Level.FINE, "Logging in");
		Map<String,String> response = httpClient(url, requestHeaders, responseHeaders, null, "GET");
		
		this.token = response.get("X-FeApi-Token");
	}
	
	public void logout() throws Exception {
		String url = getHostUrl() + "/hx/api/v1/token";
		
		Map<String,String> requestHeaders = new HashMap<>();		
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token", token);
		
		logger.log(Level.FINE, "Logging out");
		httpClient(url, requestHeaders, null, null, "DELETE");
	}
	
	
	public HostSet getHostsFromHostSet() throws Exception {
		String url = getHostUrl() + "/hx/api/v3/host_sets/" + malwareHostsetId + "/hosts";
		
		Map<String,String> requestHeaders = new HashMap<>();		
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token", token);
		
		logger.log(Level.FINE, "Getting list of hosts from HostSet id " + malwareHostsetId);
		Map<String,String> response = httpClient(url, requestHeaders, null, null, "GET");
		String json = response.get("data");
		
		if(json == null)
			throw new Exception ("JSON string is null");

		//Gson gson = new Gson();
		Gson gson = new GsonBuilder().setDateFormat("yy-MM-dd'T'HH:mm:ss.SSSX").create();
	
		return( gson.fromJson(json, HostSet.class) );		
	}
	
	
	public Host getHostById(String agentId) throws Exception {
		String url = getHostUrl() + "/hx/api/v3/hosts/" + agentId;
		
		Map<String,String> requestHeaders = new HashMap<>();		
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token", token);
		
		logger.log(Level.INFO, "Getting host by id " + agentId);
		Map<String,String> response = httpClient(url, requestHeaders, null, null, "GET");
		String json = response.get("data");
		
		if(json == null)
			throw new Exception ("JSON string is null");

		//Gson gson = new Gson();
		Gson gson = new GsonBuilder().setDateFormat("yy-MM-dd'T'HH:mm:ss.SSSX").create();
	
		HostResponse hostResponse = gson.fromJson(json, HostResponse.class);
		return( hostResponse.data );		
	}
	
	public List<Host> searchHosts(String searchTerm) throws Exception {
		String url = getHostUrl() + "/hx/api/v3/hosts" + "?search=" + searchTerm;
		
		Map<String,String> requestHeaders = new HashMap<>();		
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token", token);
		
		logger.log(Level.INFO, "Getting host by search " + searchTerm);
		Map<String,String> response = httpClient(url, requestHeaders, null, null, "GET");
		String json = response.get("data");

		if(json == null)
			throw new Exception ("JSON string is null");

		//Gson gson = new Gson();
		Gson gson = new GsonBuilder().setDateFormat("yy-MM-dd'T'HH:mm:ss.SSSX").create();
	
		HostSearch hostSearch = gson.fromJson(json, HostSearch.class);
		return( hostSearch.data.entries );		
	}

	
	public boolean addHostToHostset(String hostId) throws Exception {
		UpdateHostSet updateHostSet = new UpdateHostSet("add");
		UpdateHostSet.Change[] changes = updateHostSet.getChanges();
		UpdateHostSet.Change change = changes[0];
		String[] addHosts = new String[1];
		addHosts[0] = hostId;
		change.setAdd(addHosts);
		changes[0] = change;
		updateHostSet.setChanges(changes);
		updateHostSet.setName(malwareHostsetName);
		
		
		//generate data from pojo
		Gson gson = new Gson();
		String data = gson.toJson(updateHostSet);
				
		String url = getHostUrl() + "/hx/api/v3/host_sets/static/" + malwareHostsetId;

		Map<String,String> requestHeaders = new HashMap<>();		
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token", token);
		
		logger.log(Level.FINE, "Adding host to HostSet " + malwareHostsetId);
		Map<String,String> response = httpClient(url, requestHeaders, null, data, "PUT");
	
		//String responseCode = response.get("reponse_code");
		//String responseCode="200";
		UpdateHostSetResponse addResponse = gson.fromJson(response.get("data"), UpdateHostSetResponse.class);
		String msg = addResponse.message;
		
		//return true if message is OK
		if("OK".equals(msg))
			return(true);
		else
			return(false);
	}
	
	
	public boolean removeHostFromHostset(String hostId) throws Exception {
		UpdateHostSet updateHostSet = new UpdateHostSet("remove");
		UpdateHostSet.Change[] changes = updateHostSet.getChanges();
		UpdateHostSet.Change change = changes[0];
		String[] removeHosts = new String[1];
		removeHosts[0] = hostId;
		change.setRemove(removeHosts);
		changes[0] = change;
		updateHostSet.setChanges(changes);
		updateHostSet.setName(malwareHostsetName);
		
		
		//generate data from pojo
		Gson gson = new Gson();
		String data = gson.toJson(updateHostSet);
				
		String url = getHostUrl() + "/hx/api/v3/host_sets/static/" + malwareHostsetId;

		Map<String,String> requestHeaders = new HashMap<>();		
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token", token);
		
		logger.log(Level.FINE, "Removing host from HostSet " + malwareHostsetId);

		Map<String,String> response = httpClient(url, requestHeaders, null, data, "PUT");
	
		//String responseCode = response.get("reponse_code");
		//String responseCode="200";
		UpdateHostSetResponse removeResponse = gson.fromJson(response.get("data"), UpdateHostSetResponse.class);
		String msg = removeResponse.message;
		
		//return true if message is OK
		if("OK".equals(msg))
			return(true);
		else
			return(false);
	}
	
	
	public HostAlert getAlert(String id) throws Exception {
		String url = getHostUrl() + "/hx/api/v3/alerts/" + id;

		Map<String,String> requestHeaders = new HashMap<>();		
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token", token);
		
		logger.log(Level.INFO, "Get Alert for Id " + id);
		Map<String,String> response = httpClient(url, requestHeaders, null, null, "GET");
	
		Gson gson = new GsonBuilder().setDateFormat("yy-MM-dd'T'HH:mm:ss.SSSX").create();
		return gson.fromJson(response.get("data"), HostAlert.class);
	}
	
	//TODO
	public Map<String,String> getListHostSets(String searchTerm) throws Exception {
		String url = getHostUrl() + "/hx/api/v3/host_sets";
		
		Map<String,String> requestHeaders = new HashMap<>();
		requestHeaders.put("Accept", "application/json");
		requestHeaders.put("X-FeApi-Token",  token);
		
		logger.log(Level.FINE,  "Get List of Hostsets");
		Map<String,String> response = httpClient(url, requestHeaders, null, null, "GET");
		
		String json = response.get("data");
		logger.log(Level.INFO, "JSON: " + json);
		
		return(null);
	}
	
	private String generateAuth() {
		String auth = hxuser + ":" + hxpass;
		
		return( new String("Basic ") + new String(Base64.encodeBase64(auth.getBytes())) );
	}
	
	private String getHostUrl() {
		return("https://" + hxip + ":" + hxport);
	}

	
	private Map<String,String> httpClient(String urlStr, Map<String,String> requestHeaders, 
					Map<String,String> responseHeaders, String data, String method) throws Exception {
		    
			Map<String,String> response = new HashMap<>();
			
			logger.log(Level.INFO, "Connecting to URL " + urlStr);
			URL url = new URL(urlStr);
		    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		    //conn.setSSLSocketFactory(getSocketFactory());
		    conn.setSSLSocketFactory( (SSLSocketFactory)CustomSocketFactory.getDefault() );
		    conn.setRequestMethod(method);
		    conn.setDoOutput(true);
		    conn.setDoInput(true);
		    conn.setUseCaches(false);
		    conn.setAllowUserInteraction(false);
		    
		    if(requestHeaders != null) {
		    	for(String header : requestHeaders.keySet()) {
		    		conn.setRequestProperty(header, requestHeaders.get(header));
		    	}
		    }
		    
		    // Create POST/PUT data
		    if( ("POST".equals(method) || "PUT".equals(method)) && data != null) {
			    OutputStream out = conn.getOutputStream();
			    Writer writer = new OutputStreamWriter(out, "UTF-8");
			    writer.write(data);
	
			    writer.close();
			    out.close();
		    }

		    if (conn.getResponseCode() == 401) {
		      throw new Exception("401");
		    }
		    else if (conn.getResponseCode() == 403) {
		      throw new Exception("403");
		    }
		    else {
		    	response.put("response_code", Integer.toString(conn.getResponseCode()) );
		    }

		    //read response headers
		    if(responseHeaders != null) {
		    	for(String header : responseHeaders.keySet()) {
		    		response.put(header, conn.getHeaderField(header));
		    	}
		    }
		    
		    // Buffer the result into a string
		    BufferedReader rd = new BufferedReader(
		    new InputStreamReader(conn.getInputStream()));
		    StringBuilder sb = new StringBuilder();
		    String line;
		    while ((line = rd.readLine()) != null) {
		      sb.append(line);
		    }
		    rd.close();

		    //put data in response
		    //logger.log(Level.FINE, sb.toString());
		    response.put("data", sb.toString());
		    conn.disconnect();

		    return(response);
		  }

}
