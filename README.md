# fireeye-automation
Software suite to ingest alerts from FireEye devices and create a package of information for SOC analyst.

The app runs on Tomcat and you configure your FireEye CM to sent push alerts to the URL of the webapp.

The webapp parses the XML and extracts the most valueable information. It then uses the information to pull logs from other devices (as configured). In the included example, NetFlow logs are pulled from a host via SSH. For malware objects, VirusTotal is queried and the information included in the package. NetFlow data is converted to an Excel file and all of the data is composed in an email which is sent to 1 or more recipients.

In addition, the app uses FireEye HX API to add hosts to a hostset. You can configure the host set on your FireEye devices to perform any level of increased monitoring. A seperate process runs each day to manage the hostset. If hosts have not alerted any more in the last 7 days, they are removed from the hostset and the advanced monitoring.
