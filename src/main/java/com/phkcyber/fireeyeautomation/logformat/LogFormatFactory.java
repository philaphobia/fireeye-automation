package com.phkcyber.fireeyeautomation.logformat;

import javax.servlet.ServletContext;
import java.util.logging.*;

public class LogFormatFactory {
	private static final Logger logger = Logger.getLogger("LogFormatFactory");
	
	private static final String _logformatAttribute="XTRACT_logstorage_format";
	
	public static LogEntry getInstance(ServletContext ctx) throws Exception {
		String logformatType = getLogFormatType(ctx);
		
		logger.log(Level.FINE, "LogFormatType: " + logformatType);
				
		if("silk".equalsIgnoreCase(logformatType))
			return(new LogEntrySilk());
		
		else {
			throw new Exception("Unknown logstorage type: " + logformatType + " requested");
		}

	}

	
	private static String getLogFormatType(ServletContext ctx) {
		return( (String) ctx.getAttribute(_logformatAttribute) );
	}
}
