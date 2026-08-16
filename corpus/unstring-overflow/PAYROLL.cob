       IDENTIFICATION DIVISION.
       PROGRAM-ID. PAYROLL.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-INPUT       PIC X(50).
       01 WS-NOMBRE      PIC X(10).
       01 WS-APELLIDO    PIC X(10).
       PROCEDURE DIVISION.
           UNSTRING WS-INPUT
               DELIMITED BY SPACE
               INTO WS-NOMBRE
                    WS-APELLIDO.
           STOP RUN.
