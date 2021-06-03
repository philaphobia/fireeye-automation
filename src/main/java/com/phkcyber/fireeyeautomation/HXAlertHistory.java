package com.phkcyber.fireeyeautomation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import com.phkcyber.fireeyeautomation.pojo.HXAgentHistory;

public class HXAlertHistory {
	private static String jsonFilename = "/opt/tools/conf/hx_agent_alert_history.json";
	
	public HXAlertHistory() {
	}
	
	public HXAgentHistory readJson() throws FileNotFoundException,Exception {
		File jsonFile=null;
		InputStream is=null;
		Reader reader=null;
		
		try {
			jsonFile = new File(jsonFilename);
			is = new FileInputStream(jsonFile);
			reader = new InputStreamReader(is, "UTF-8");
			
			Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX").create();

			return( gson.fromJson(reader, HXAgentHistory.class) );
		}
		catch(FileNotFoundException fnfe) {
			System.err.println("File Not Found Exception: " + fnfe.getMessage());
			throw new FileNotFoundException();
		}
		catch(Exception e) {
			System.err.println("Other Exception: " + e.getMessage());
			throw new Exception(e);
		}
		finally {
			try {
				if(reader != null)
					reader.close();
				if(is !=null)
					is.close();
			}
			catch(Exception e) {
				//ignore exceptions
			}
		}
	}
	
	public void writeJson(HXAgentHistory hxAgentHistory) throws Exception {
		File jsonFile=null;
		OutputStream os=null;
		Writer writer=null;
		
		try {
			jsonFile = new File(jsonFilename);
			os = new FileOutputStream(jsonFile, false); //set false to overwrite vs append
			writer = new OutputStreamWriter(os, "UTF-8");
			
			Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX").create();
			//Gson gson = new GsonBuilder().create();
			gson.toJson(hxAgentHistory, writer);
		}
		catch(Exception e) {
			throw new Exception(e);
		}
		finally {
			try {
				if(writer != null)
					writer.close();
				if(os !=null)
					os.close();
			}
			catch(Exception e) {
				//ignore exceptions
			}
		}
	}
}
