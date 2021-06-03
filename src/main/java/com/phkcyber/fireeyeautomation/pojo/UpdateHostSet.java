package com.phkcyber.fireeyeautomation.pojo;

public class UpdateHostSet {
	private String name;
	private Change[] changes;
	
	public UpdateHostSet(String cmd) {
		changes = new Change[1];
		changes[0] = new Change(cmd);
	}
	public void setName(String name) {
		this.name =name;
	}
	public void setChanges(Change[] changes) {
		this.changes = changes;
	}
	
	public Change[] getChanges() {
		return this.changes;
	}
	
	public class Change {
		private String command="change"; //command is always change
		private String[] add;
		private String[] remove;

		public Change(String cmd) {
			if("add".equals(cmd))
				add = new String[0];
			else if("remove".equals(cmd))
				remove = new String[0];
		}
		//public void setCommand(String command) {
		//	this.command = command;
		//}
		public void setAdd(String[] add) {
			this.add = add;
		}
		public void setRemove(String[] remove) {
			this.remove = remove;
		}
	}
}
