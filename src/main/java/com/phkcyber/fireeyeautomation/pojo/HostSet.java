package com.phkcyber.fireeyeautomation.pojo;

import java.util.List;

public class HostSet {
	public Data data;
	public String message;
	//List<String> details;
	public String route;
	
	public class Data {
		public int total;
		public List<Host> entries;
	}//class Data

	
	public HostSet() {
	}
}
