       IDENTIFICATION DIVISION.
       PROGRAM-ID. SAFEUNSTRING.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-INPUT       PIC X(50).
       01 WS-NOMBRE      PIC X(10).
       01 WS-APELLIDO    PIC X(10).
       01 WS-OVERFLOW    PIC X VALUE 'N'.
       PROCEDURE DIVISION.
           UNSTRING WS-INPUT
               DELIMITED BY SPACE
               INTO WS-NOMBRE
                    WS-APELLIDO
               ON OVERFLOW
                   MOVE 'Y' TO WS-OVERFLOW.
           STOP RUN.
