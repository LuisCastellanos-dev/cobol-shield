       IDENTIFICATION DIVISION.
       PROGRAM-ID. MULTILINE.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-DATA        PIC X(100).
       01 WS-PART1       PIC X(20).
       01 WS-PART2       PIC X(20).
       01 WS-PART3       PIC X(20).
       PROCEDURE DIVISION.
           UNSTRING WS-DATA
               DELIMITED BY ','
               INTO WS-PART1
                    WS-PART2
                    WS-PART3
               TALLYING IN WS-COUNT.
           STOP RUN.
