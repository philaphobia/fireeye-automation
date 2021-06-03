package com.phkcyber.fireeyeautomation.virustotal;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class VTResponse {
  public Data data;

  public class Data {
    public Attributes attributes;

    public class Attributes {
      public String meaningful_name;
      public List<CrowdSourcedResults> crowdsourced_yara_results;
      public LastAnalysisResults last_analysis_results;
      public LastAnalysisStats last_analysis_stats;
      public TotalVotes total_votes;
      public TrustedVerdict trusted_verdict;
      public List<Trid> trid;

      public class CrowdSourcedResults {
        public String description;
      }//class CrowdSourcedResults

      public class LastAnalysisResults {
        public MAX MAX;

        public class MAX {
          public String result;
        }
      }//class LastAnalysisResults

      public class LastAnalysisStats { 
        @SerializedName("confirmed-timeout")
        int confirmed_timeout;
        int failure;
        int harmless;
        int malicious;
        int suspicious;
        int timeout;
        @SerializedName("type-unsupported")
        int type_unsupported;
        int undetected;
      }//class LastAnalysisStats

      public class TotalVotes {
        String harmless;
        String malicious;
      }//class TotalVotes


      public class TrustedVerdict {
        String filename;
        String link;
        String organization;
        String verdict;
      }//class TrustedVerdict

      public class Trid {
        public String file_type;
        public String probability;
      }//class Trid

    }//class Attributes

  }//class Data

}

