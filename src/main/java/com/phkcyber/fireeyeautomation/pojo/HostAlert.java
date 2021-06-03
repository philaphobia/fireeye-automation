package com.phkcyber.fireeyeautomation.pojo;

import java.util.Date;
import java.util.List;

public class HostAlert {
	public String route;
	public Data data;
	
	public class Data {
		public String _id;
		public Agent agent;
		public Condition condition;
		public Date event_at;
		public Date matched_at;
		public Date reported_at;
		public String source;
		public List<MatchedSourceAlerts> matched_source_alerts;
		public String resolution;
		public String url;
		public int event_id;
		public String event_type;
		public EventValues event_values;
		public String message;
		
		public class Agent {
			public String _id;
			public String url;
			public String containment_state;
		}
		
		public class Condition {
			public String _id;
			public String url;
		}
		
		public class MatchedSourceAlerts {
			public String _id;
			public String url;
			public String appliance_id;
			public String meta;
			public String indicator_revision;
			public String indicator_id;
			public int row;
		}
		
		public class EventValues {
			//TODO
		}
	}
}
