package com.phkcyber.fireeyeautomation.pojo;

import java.util.List;

public class HostList {
	int total;
	//Query query
	//Sort sort;
	int offset;
	int limit;
	
	Data data;
	String message;
	//List<String> details;
	String route;
	
	public class Data {
		int total;
		List<Host> entries;
	}//class Data

	public HostList() {
	}
}
