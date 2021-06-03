package com.phkcyber.fireeyeautomation.pojo;

public class UpdateHostSetResponse {
	//List<String> details
	String route;
	public Data data;
	public String message;

	public class Data {
		String _id;
		String name;
		String _revision;
		String url;
	}
}
