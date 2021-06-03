package com.phkcyber.fireeyeautomation.logformat;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import java.util.logging.*;

/**
 * Method to implement the LogEntry structure and values for SiLK logs;
 * 
 * @author Philip Kulp <philip@phkcyber.com>
 *
 */

public class LogEntrySilk extends LogEntry {
	private static final Logger logger = Logger.getLogger("LogEntrySilk");
	
	private final SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd'T'HH:mm:ss.SSS", Locale.US);
	private final SimpleDateFormat dfJustTime = new SimpleDateFormat("HH:mm:ss", Locale.US);
	private final SimpleDateFormat dfJustDate = new SimpleDateFormat("yyyy'-'MM'-'dd", Locale.US);
	
	//empty variables  
	public LogEntrySilk() {
		
	} 
  
	//parse the raw text for parsing and populating
	public LogEntrySilk(String text) {
		super();
		
		String[] fields = text.split("\\|");

		//match and add src
		if(fields[0].matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))
			setSrc(fields[0]);

		//match and add dst
		if(fields[1].matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))
			setDst(fields[1]);

		//set src port
		try {
			setSrcPort( Integer.parseInt(fields[2]) );
		}
		catch(NumberFormatException e) {
			setSrcPort(0);
		}

		//set dst port
		try {
			setDstPort( Integer.parseInt(fields[3]) );
		}
		catch(NumberFormatException e) {
			setDstPort(0);
		}

		//set protocol 
		try {
			setProto( Integer.parseInt(fields[4]) );
		}
		catch(NumberFormatException e) {
			setProto(0);
		}

		//set sent and rcvd 
		try {
			setSent( Integer.parseInt(fields[6]) );
			setRcvd( Integer.parseInt(fields[6]) );
		}
		catch(NumberFormatException e) {
			setSent(0);
			setRcvd(0);
		}

		//try to parse the date
		try {
			Date tmpDate = df.parse( fields[8] );
			setItime( tmpDate.getTime() );
			setDate( dfJustDate.format(tmpDate));
			setTime( dfJustTime.format(tmpDate) );
		}
		catch(ParseException e) { 
			logger.log(Level.WARNING, "Failed to parse date");
		}
		
		//set duration
		try {
			setDuration( Math.round( Float.parseFloat(fields[9])) );
		}
		catch(NumberFormatException e) {
			setDuration(0);
		}
		
		//set the sensor to type
		setType(fields[10]);
		
		//set source country
		if(! fields[11].contains("--") )
			setSrcCountry(fields[11]);
		
		//set dest country
		if(! fields[12].contains("--") )
			setDstCountry(fields[12]);
		
		//set application to the method
		setApplication(fields[13]);
  }

}
