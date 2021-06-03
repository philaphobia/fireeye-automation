package com.phkcyber.fireeyeautomation.common;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Common {
	public static Date parseDates(String strDate) {
		DateFormat dfWithMilli = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX");
		DateFormat dfWithoutMilli = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
		DateFormat dfWithMillandOffset = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZZ");
		
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
		
		//without milli
		try {
			return dfWithMillandOffset.parse(strDate);
		}
		catch (Exception e) {
			//ignore faile
		}
		//no luck just return now
		return( new Date());
	}
}
