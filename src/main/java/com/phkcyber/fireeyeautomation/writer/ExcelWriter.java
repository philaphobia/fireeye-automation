package com.phkcyber.fireeyeautomation.writer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.text.SimpleDateFormat;
import java.math.BigDecimal;
import java.math.RoundingMode;

import java.util.Locale;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.ss.util.CellReference;
import org.apache.poi.xssf.usermodel.XSSFDataFormat;
import org.apache.poi.xssf.streaming.SXSSFWorkbook;

public class ExcelWriter {
  private SXSSFWorkbook wb;
  private Sheet shLogs; 
  private int currentRow;
  //private String outputFile;

  private CellStyle styleWrapText=null;
  private CellStyle csExcelDate=null;
  //CellStyle csHyperLink=null;

  private String[] fields = {"src","dst","sport","dport","proto","bytes","timestamp","duration","dst_country","application"};
    
  private CreationHelper createHelper=null;
  
  private SimpleDateFormat dfDateTime = new SimpleDateFormat("MM-dd-yyyy HH:mm:ss", Locale.US);

  public ExcelWriter() {
 
    //create the workbook 
    wb = new SXSSFWorkbook(100);


    //create summary tab
    shLogs = wb.createSheet("Logs");
    shLogs.setColumnWidth(0,15*256);
    shLogs.setColumnWidth(1,15*256);
    shLogs.setColumnWidth(2,8*256);
    shLogs.setColumnWidth(3,8*256);
    shLogs.setColumnWidth(4,8*256);
    shLogs.setColumnWidth(5,10*256);
    shLogs.setColumnWidth(6,15*256);
    shLogs.setColumnWidth(7,10*256);
    shLogs.setColumnWidth(8,10*256);
    shLogs.setColumnWidth(9,10*256);

    currentRow=0;
    //outputFile = fileName;


    //create sheet header info
   // shLogs = createHeader(shLogs,"Logs");

    //create header for accepted risk
    Row rowLogs = shLogs.createRow(0);
    int i=0;
    for(String field : fields) {
    	rowLogs.createCell(i).setCellValue(field);
    	//createCell(rowLogs, i, field, createHeaderStyle());
    	i++;
    }
    currentRow++;

    //create freeze panes
    //shLogs.createFreezePane(1,1);

    //create date format
    DataFormat dfExcelDate = wb.createDataFormat();
    csExcelDate = wb.createCellStyle();
    csExcelDate.setDataFormat(dfExcelDate.getFormat("mm/dd/yyyy"));

    //instantiate the create helper
    createHelper = wb.getCreationHelper();
  }

/**
   public void addRow(String host, String fqdn, String netbios, ReportItem item, Date firstSeenDate) {

    Row rowSummary = shSummary.createRow(currentRow);
    rowSummary.createCell(0).setCellValue(host);

    Row rowFull = shFull.createRow(currentRow);
    rowFull.createCell(0).setCellValue(host);

    //get FQDN or netbios name
    if( (fqdn != null) && (! fqdn.equals("")) ) {
      rowSummary.createCell(1).setCellValue(fqdn);
      rowFull.createCell(1).setCellValue(fqdn);
    }
    else if(netbios != null) {
      rowSummary.createCell(1).setCellValue(netbios);
      rowFull.createCell(1).setCellValue(netbios);
    }

    if(item.getProtocol() != null) {
      rowSummary.createCell(2).setCellValue(item.getPort() + "/" + item.getProtocol());
      rowFull.createCell(2).setCellValue(item.getPort() + "/" + item.getProtocol());
    }
    else {
      rowSummary.createCell(2).setCellValue(item.getPort());
      rowFull.createCell(2).setCellValue(item.getPort());
    }

    if(item.getSvcName() != null) {
      rowSummary.createCell(3).setCellValue(item.getSvcName());
      rowFull.createCell(3).setCellValue(item.getSvcName());
    }

    if(item.getRisk() != null) {
      rowSummary.createCell(4).setCellValue(item.getRisk());
      rowFull.createCell(4).setCellValue(item.getRisk());
    }

//    if(item.getCvss() > 0) {
//      rowSummary.createCell(5).setCellValue(item.getCvss());
//      rowFull.createCell(5).setCellValue(item.getCvss());
//    }

    if(item.getCvss() > 0) {
      Cell cellSummaryCvss = rowSummary.createCell(5);
      Cell cellFullCvss = rowFull.createCell(5);
      cellSummaryCvss.setCellType(Cell.CELL_TYPE_NUMERIC);
      cellFullCvss.setCellType(Cell.CELL_TYPE_NUMERIC);

      try {
        cellSummaryCvss.setCellValue( new BigDecimal(item.getCvss()).setScale(1, RoundingMode.UP).doubleValue());
        cellFullCvss.setCellValue( new BigDecimal(item.getCvss()).setScale(1, RoundingMode.UP).doubleValue());
      }
      catch(Exception e) {
        cellSummaryCvss.setCellValue( item.getCvss() );
        cellFullCvss.setCellValue( item.getCvss() );
      }
    }

   
    if(firstSeenDate != null) {
      Cell cellFirstSeenDate = rowFull.createCell(6);
      cellFirstSeenDate.setCellStyle(csExcelDate);
      cellFirstSeenDate.setCellValue(firstSeenDate);
    }

//    if(item.getCvssTemporal() > 0) {
//      Cell cellCvssTemp = rowFull.createCell(6);
//      cellCvssTemp.setCellType(Cell.CELL_TYPE_NUMERIC);
//
//      try {
//        cellCvssTemp.setCellValue( new BigDecimal(item.getCvssTemporal()).setScale(1, RoundingMode.UP).doubleValue());
//      }
//      catch(Exception e) {
//        cellCvssTemp.setCellValue( item.getCvssTemporal() );
//      } 
//    }

    if((item.getPluginId() > 0) && (item.getPluginName() != null) ) {
      Cell cellPluginSummary = rowSummary.createCell(6);
      cellPluginSummary.setCellValue(item.getPluginId() + ": " + item.getPluginName());

      Cell cellPluginFull = rowFull.createCell(7); 
      cellPluginFull.setCellValue(item.getPluginId() + ": " + item.getPluginName());

      //create hyperlink to tenable plugin page
      Hyperlink link = createHelper.createHyperlink(Hyperlink.LINK_URL);
      link.setAddress(tenablePluginUrl + item.getPluginId());

      //add hyperlink to cells
      cellPluginSummary.setHyperlink(link);
      cellPluginSummary.setCellStyle(csHyperLink);

      cellPluginFull.setHyperlink(link);
      cellPluginFull.setCellStyle(csHyperLink);
    }

    if(item.getSynopsis() != null) {
      rowSummary.createCell(7).setCellValue(item.getSynopsis());
    }

    //rest of columns are for full report

    if(item.getCve() != null) {
      rowFull.createCell(8).setCellValue(item.getCve());
    }

    //dates
    if(item.getPluginPublicationDate() != null) {
      Cell cellDate = rowFull.createCell(9);
      cellDate.setCellValue(item.getPluginPublicationDate());
      cellDate.setCellStyle(csExcelDate); 
    }
    if(item.getPatchPublicationDate() != null) {
      Cell cellDate = rowFull.createCell(10);
      cellDate.setCellValue(item.getPatchPublicationDate());
      cellDate.setCellStyle(csExcelDate); 
    }
    if(item.getVulnerabilityPublicationDate() != null) {
      Cell cellDate = rowFull.createCell(11);
      cellDate.setCellValue(item.getVulnerabilityPublicationDate());
      cellDate.setCellStyle(csExcelDate); 
    }


    if(item.getVendorLink() != null) {
      rowFull.createCell(12).setCellValue(item.getVendorLink());
    }

    if(item.getDescription() != null) {
      rowFull.createCell(13).setCellValue(item.getDescription());
    }

    if(item.getPluginOutput() != null) {
      rowFull.createCell(14).setCellValue(item.getPluginOutput());
    }


    //update row number
    this.currentRow++;
  }
**/


  public void addRows(List<Map<String,Object>> logs) {
	  Row row=null;
	  int i=0;
	  
	  for( Map<String,Object> log : logs ) {
		  row = shLogs.createRow(currentRow);
		  i=0;
		  
		  for(String field : fields) {
			if(log.get(field) instanceof Integer) {
			  row.createCell(i).setCellValue(String.valueOf((Integer)log.get(field)));
			}
			else if(log.get(field) instanceof Float) {
			  row.createCell(i).setCellValue(String.valueOf((Float)log.get(field)));
			}
			else if(log.get(field) instanceof Date) {
			  Cell cellDate = row.createCell(i);
			  cellDate.setCellValue(dfDateTime.format((Date)log.get(field)));
      			  cellDate.setCellStyle(csExcelDate);
			}
			else {
			  row.createCell(i).setCellValue((String)log.get(field));
			}

			i++;
		  }
		
		  currentRow++;
	  }

  }

/**
  public void addRowCompliance(String host, String fqdn, String netbios, ReportItem item) {
    Row rowCompliance = shCompliance.createRow(currentComplianceRow);

    rowCompliance.createCell(0).setCellValue(host);

    //get FQDN or netbios name
    if( (fqdn != null) && (! fqdn.equals("")) ) {
      rowCompliance.createCell(1).setCellValue(fqdn);
    }
    else if(netbios != null) {
      rowCompliance.createCell(1).setCellValue(netbios);
    }

    //set the risk
    if(item.getRisk() != null) {
      rowCompliance.createCell(2).setCellValue(item.getRisk());
    }

    //set the description
    if(item.getDescription() != null) {
      rowCompliance.createCell(3).setCellValue(item.getDescription());
    }

    if(item.getPluginOutput() != null) {
      rowCompliance.createCell(4).setCellValue(item.getPluginOutput());
    }

    currentComplianceRow++;
  }
**/

  public String writeFile() throws Exception {
	File tempFile = File.createTempFile("fireeye-", "-netflow");
	  
    try {
      FileOutputStream out = new FileOutputStream(tempFile);
      wb.write(out);
      out.close();
      wb.dispose();
      
      return(tempFile.getAbsolutePath());
    }
    catch(FileNotFoundException fnfe) {
      fnfe.printStackTrace();
      throw new Exception("File Not Found " + tempFile.getAbsolutePath());
    }
    catch(IOException ioe) {
      ioe.printStackTrace();
      throw new Exception("Cannot write file " + tempFile.getAbsolutePath());
    }
  }

/**
  private Sheet createHeader(Sheet sh, String shType, Date startTime, Date endTime, String scanName) {
    CellStyle headerStyle = createHeaderStyle();
    CellStyle dateHeaderStyle = createDateHeaderStyle();
    CellStyle dateStyle = createDateStyle();

    //first row
    Row rowOne = sh.createRow(0);
    createHeaderCell(rowOne, 1, "Scan Started:", dateHeaderStyle);
    Cell dateStart = rowOne.createCell(2);
         dateStart.setCellValue(startTime);
         dateStart.setCellStyle(dateStyle);

    //second row
    Row rowTwo = sh.createRow(1);
    createHeaderCell(rowTwo, 1, "Scan Ended:", dateHeaderStyle);
    Cell dateEnd = rowTwo.createCell(2);
         dateEnd.setCellValue(endTime);
         dateEnd.setCellStyle(dateStyle);

    //third row with scan name
    Row rowThree = sh.createRow(2);
    createHeaderCell(rowThree, 1, "Scan Name:", dateHeaderStyle);
    Cell cellScanName = rowThree.createCell(2);
         cellScanName.setCellValue(scanName);


    //set header row with text
    Row row = sh.createRow(3);

    createHeaderCell(row, 0, "Host", headerStyle);
    createHeaderCell(row, 1, "Name", headerStyle);
    createHeaderCell(row, 2, "Port", headerStyle);
    createHeaderCell(row, 3, "Service", headerStyle);
    createHeaderCell(row, 4, "Risk", headerStyle);
    createHeaderCell(row, 5, "CVSS", headerStyle);
    createHeaderCell(row, 6, "Plugin ID / Title", headerStyle);
    createHeaderCell(row, 7, "Synopsis", headerStyle);

    if(shType.equals("Full")) {
      createHeaderCell(row, 6, "First Seen", headerStyle);
      createHeaderCell(row, 7, "Plugin ID / Title", headerStyle);
      createHeaderCell(row, 8, "CVE", headerStyle);
      createHeaderCell(row, 9, "Plugin Pub. Date", headerStyle);
      createHeaderCell(row, 10, "Plugin Mod. Date", headerStyle);
      createHeaderCell(row, 11, "Vuln. Pub. Date", headerStyle);
      createHeaderCell(row, 12, "Vendor Link", headerStyle);
      createHeaderCell(row, 13, "Description", headerStyle);
      createHeaderCell(row, 14, "Plugin Output", headerStyle);
    }

    //update row number to account for header, dates, etc
    this.currentRow=4;

    return(sh);
  }


  private Cell createHeaderCell(Row row, int colNum, String cellText, CellStyle cellStyle) {
    Cell newCell = row.createCell(colNum);
    newCell.setCellValue(cellText);
    newCell.setCellStyle(cellStyle);

    return(newCell);
  }
 **/
  
  private CellStyle createHeaderStyle() {
    CellStyle cellStyle = wb.createCellStyle();
    Font font = wb.createFont();

//    font.setFontName(Font.FONT_ARIAL);  
    font.setFontHeightInPoints((short) 12);  
    font.setBoldweight(Font.BOLDWEIGHT_BOLD);  
    cellStyle.setFont(font);
    cellStyle.setAlignment(CellStyle.ALIGN_CENTER);

    return(cellStyle);
  } 

  private CellStyle createDateHeaderStyle() {
    CellStyle cellStyle = wb.createCellStyle();
    Font font = wb.createFont();

    font.setBoldweight(Font.BOLDWEIGHT_BOLD);
    cellStyle.setFont(font);

    return(cellStyle);
  }

  private CellStyle createDateStyle() {
    CellStyle cellStyle = wb.createCellStyle();
    cellStyle.setDataFormat((short)0x16);

    return(cellStyle);
  }

  private void createStyles() {
    styleWrapText = wb.createCellStyle();
    styleWrapText.setWrapText(true);
  }


  private String createStringDate(Date date) {
    SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy");

    try {
      return(df.format(date));
    }
    catch(Exception e) {
      return("");
    }
  }


  private Date fakeDate() {
    String tmpDate = "1970-01-01";

    try {
      SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

      return(dateFormat.parse(tmpDate));
    }
    catch(Exception e) {
      return(null);
    }

  }

}
