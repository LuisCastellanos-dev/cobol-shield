000100 IDENTIFICATION DIVISION.                                                 
000200 PROGRAM-ID. BOUNDARY-TEST.                                               
000300 DATA DIVISION.                                                           
000400 WORKING-STORAGE SECTION.                                                 
000500 01 WS-BALANCE  PIC 9(10) VALUE ZEROS.                            PROG0042
000600 PROCEDURE DIVISION.                                                      
000700     MOVE 0 TO WS-BALANCE.                                                
000800     STOP RUN.                                                            
