000100 IDENTIFICATION DIVISION.                                                 
000200 PROGRAM-ID. COL7-TEST.                                                   
000300 DATA DIVISION.                                                           
000400 WORKING-STORAGE SECTION.                                                 
000500 01 WS-BALANCE  PIC 9(10) VALUE ZEROS.                                    
000600*MOVE 999999 TO WS-BALANCE                                                
000700 PROCEDURE DIVISION.                                                      
000800     MOVE 1000 TO WS-BALANCE.                                             
000900     STOP RUN.                                                            
