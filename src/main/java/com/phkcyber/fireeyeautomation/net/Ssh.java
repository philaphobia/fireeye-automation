package com.phkcyber.fireeyeautomation.net;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import com.jcraft.jsch.*;



public class Ssh {
	private static JSch jsch;
	private static Session session;

	private String user=null;
	private String keyPath=null;
	private String host=null;
	private int port=22;

	public Ssh(String user, String keyPath, String host) throws Exception {
		this.user = user;
		this.keyPath = keyPath;
		this.host = host;
	}
	  
	public void connect() throws Exception {
		try {
			jsch=new JSch();
			jsch.addIdentity(keyPath);
			session=jsch.getSession(user, host, port);
			session.setConfig("StrictHostKeyChecking","no");
			session.connect();
		}
		catch(JSchException jse) {
			jse.printStackTrace();
			throw new Exception("Problem connecting with SSH as user: " + user + " to host: " + host);
		}
	}

	public List<String> execCmd(String cmd) throws Exception {
		//make sure we have a valid connected session
		if( (session == null) || (! session.isConnected()))
			connect();
			
		try {
			Channel channel=session.openChannel("exec");
			((ChannelExec)channel).setPty(true);
			((ChannelExec)channel).setCommand(cmd);
 
			channel.setXForwarding(false);
 
			//channel.setInputStream(System.in);
			channel.setInputStream(null);
			//channel.setOutputStream(System.out);
 
			((ChannelExec)channel).setErrStream(System.err);
 
			InputStream in=channel.getInputStream();
 
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(in));
      
			channel.connect();
      
			List<String> output = new ArrayList<>();
			String s;
			String[] pieces;
			while((s = stdInput.readLine()) != null ) {
				//test lines to remove ones without source...most likely the header
				pieces = s.split("\\|");
				if( (pieces != null) && (pieces.length > 0)) {
					if(pieces[0].trim().matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))
						output.add(s);
				}
			}

			channel.disconnect();
			session.disconnect();

			return(output);
		}
		catch(IOException ioe){
			throw new Exception(ioe);
		}
		catch (JSchException jse) {
			throw new Exception(jse);
		}

	}

	
	public void close() {
		if( (session != null) && (session.isConnected()))
			session.disconnect();
	}
}
