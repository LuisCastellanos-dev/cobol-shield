       IDENTIFICATION DIVISION.
       PROGRAM-ID. SAFESTRING.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-A           PIC X(10).
       01 WS-B           PIC X(10).
       01 WS-RESULT      PIC X(25).
       01 WS-OK          PIC X VALUE 'N'.
       PROCEDURE DIVISION.
           STRING WS-A DELIMITED SPACE
                  WS-B DELIMITED SPACE
                  INTO WS-RESULT
               NOT ON OVERFLOW
                   MOVE 'Y' TO WS-OK.
           STOP RUN.
