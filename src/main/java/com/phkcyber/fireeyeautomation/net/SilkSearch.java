package com.phkcyber.fireeyeautomation.net;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TimeZone;

import java.util.logging.*;

import com.phkcyber.fireeyeautomation.logformat.LogEntry;
import com.phkcyber.fireeyeautomation.logformat.LogEntrySilk;
import com.phkcyber.fireeyeautomation.net.Ssh;


public class SilkSearch {
	private static Logger logger=null;
	
	private final SimpleDateFormat dfDate = new SimpleDateFormat("yyyy/MM/dd", Locale.US);
	private final SimpleDateFormat dfTime = new SimpleDateFormat("yyyy/MM/dd:HH:mm:ss.SSS", Locale.US);
	private final String rwfilterBin="/usr/local/bin/rwfilter --type=all --pass=stdout";
	private final String rwcutBin = "/usr/local/bin/rwcut --fields=1-10,12,18,19,29 --no-col";
	private long maxRunTime=1000 * 60 * 5; //5 mintues
	private static final String user="";
	private static final String host="";
	private static final String keyFile="/opt/tools/conf/netflow.id_rsa";
	
	
	public SilkSearch() {
		logger = Logger.getLogger("SilkSearch");
	
		dfDate.setTimeZone(TimeZone.getTimeZone("UTC"));	
		dfTime.setTimeZone(TimeZone.getTimeZone("UTC"));	
	}

	public List<LogEntry> search(Calendar start, Calendar end, String cidr, int maxLogs) throws Exception {
		//if src and dst are empty this will be bad so return nothing
		/**
		if( (src==null) && (dst==null)) {

			logger.log(Level.INFO, "Search requested with no source or destination, returning empty results");
			return(new ArrayList<LogEntry>());
		}
		**/
		
		StringBuffer rwfilterExec = new StringBuffer();
		rwfilterExec.append(rwfilterBin);
		rwfilterExec.append(" --start-date=" + dfDate.format(start.getTime()));
		rwfilterExec.append(" --end-date=" + dfDate.format(end.getTime()));
		//rwfilterExec.append(" --active-time=" + dfTime.format(start.getTime()) + "-" + dfTime.format(end.getTime()));
		
		
		if(cidr != null)
			rwfilterExec.append(" --any-cidr=" + cidr);
		
		String cmd = rwfilterExec.toString() + " | " + rwcutBin + " --num-recs=" + maxLogs;
		
		System.out.println("Executing command: " + cmd);
		logger.log(Level.FINE, "Silk Command: " + cmd);
			
		return( execRwfilter(cmd) );
	}

	
	public List<LogEntry> search(Calendar calSearch, String srcCidr, String dstCidr, int maxLogs) throws Exception {
		//if src and dst are empty this will be bad so return nothing
		if( (srcCidr==null) && (dstCidr==null)) {

			logger.log(Level.INFO, "Search requested with no source or destination, returning empty results");
			return(new ArrayList<LogEntry>());
		}
		
		StringBuffer rwfilterExec = new StringBuffer();
		rwfilterExec.append(rwfilterBin);
		rwfilterExec.append(" --start-date=" + dfDate.format(calSearch.getTime()));
		rwfilterExec.append(" --end-date=" + dfDate.format(calSearch.getTime()));
		

		String searchCidr=null;
		// get all logs from the malicious IP
		if(srcCidr != null) { 
			if(srcCidr.trim().matches("^10\\..*") || srcCidr.trim().matches("^207\\.245\\.160.*")) {
				//skip since it is local IP
			}
			else {
				searchCidr=srcCidr;
			}
		}
		
		//check the dstCidr only if searchCidr has not already been defined
		else if(dstCidr != null && searchCidr == null) {
			if(dstCidr.trim().matches("^10\\..*") || dstCidr.trim().matches("^207\\.245\\.160.*")) {
				//skip since it is local IP
			}
			else {
				searchCidr=dstCidr;
			}
		}
		
		//check if the searchCidr failed to populate
		if(searchCidr == null) {
			if(srcCidr != null)
				rwfilterExec.append(" --scidr=" + srcCidr);
			
			if(dstCidr != null)
				rwfilterExec.append(" --dcidr=" + dstCidr);
		}
		else {
			rwfilterExec.append(" --any-cidr=" + searchCidr);
		}
		
		String cmd = rwfilterExec.toString() + " | " + rwcutBin + " --num-recs=" + maxLogs;
		
		System.out.println("Executing command: " + cmd);
		logger.log(Level.FINE, "Silk Command: " + cmd);
			
		return( execRwfilter(cmd) );
	}

	
	private List<LogEntry> execRwfilter(String cmd) throws Exception {
		List<LogEntry> logs = new ArrayList<>();
		List<String> output;
		
		//create a time that will expire to set a limit for nmap run time
		Timer timer = new Timer(true);
		InterruptTimerTask interruptTimerTask = new InterruptTimerTask(Thread.currentThread());

		Ssh ssh=null;
		
		try {
			timer.schedule(interruptTimerTask, maxRunTime);

			ssh = new Ssh(user, keyFile, host);
			ssh.connect();

			output = ssh.execCmd(cmd);
			
			LogEntrySilk entry;

			//int logsFound=0;
			for(String line : output) {
				entry=null;

				//if max hit return logs
				//if(logsFound >= maxLogs)
				//	return(logs);
	
				
				if(line != null) {
					entry = new LogEntrySilk(line);
					logs.add(entry);
					//logsFound++;
				}
			}
			
			return(logs);
		} 
		catch (SecurityException se) {
			throw new Exception(se);
		}
		finally {
			if(ssh != null)
				ssh.close();
		}

	}

	
	/*
	 * A TimerTask that interrupts the specified thread when run.
	 */
	protected class InterruptTimerTask extends TimerTask {
		private Thread theTread;

		public InterruptTimerTask(Thread theTread) {
			this.theTread = theTread;
		}

		public void run() {
			theTread.interrupt();
		}
	}

} 
