package com.phkcyber.fireeyeautomation.pojo;

import com.google.gson.annotations.SerializedName;

public class FireEyeAlert {
	public String msg;
	public String appliance;
	public String version;
	public String product;
	@SerializedName("appliance-id")
	public String applianceId;
	public Alert alert;
	
	public class Alert {
		public String name;
	}
}
