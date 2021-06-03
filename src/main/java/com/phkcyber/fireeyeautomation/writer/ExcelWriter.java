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
import org.apache.poi.xssf.usermodel.XSSFFont;

public class ExcelWriter {
  private SXSSFWorkbook wb;
  private Sheet shLogs; 
  private int currentRow;

  private CellStyle styleWrapText=null;
  private CellStyle csExcelDate=null;

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
  
  private CellStyle createHeaderStyle() {
    CellStyle cellStyle = wb.createCellStyle();
    Font font = wb.createFont();

    font.setFontHeightInPoints((short) 12);  
    font.setBold(true);
    cellStyle.setFont(font);
    cellStyle.setAlignment(HorizontalAlignment.CENTER);

    return(cellStyle);
  } 

  private CellStyle createDateHeaderStyle() {
    CellStyle cellStyle = wb.createCellStyle();
    Font font = wb.createFont();

    font.setBold(true);
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
