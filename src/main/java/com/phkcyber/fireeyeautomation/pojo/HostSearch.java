package com.phkcyber.fireeyeautomation.pojo;

import java.util.List;

public class HostSearch {
	public Data data;
	public String message;
	//public List<String> details;
	public String route;
	
	public class Data {
		public int total;
		public Query query;
		//public Sort sort;
		public int offset;
		public int limit;
		public List<Host> entries;

		public class Query {
			public String search;
		}
	
	}//class Data

	public HostSearch() {
	}
}
