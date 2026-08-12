      *> COBOL Shield - Byte-level invisible character auditor
      *> Compatible with GnuCOBOL 3.x
      *> Detects: C0 controls, U+200B (Zero-Width), U+202E (Bidi Override)
      *> Ref: CVE-2021-42574 (Trojan Source)

       IDENTIFICATION DIVISION.
       PROGRAM-ID. AUDITOR-INVISIBLE.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-REGISTRO          PIC X(50).
       01 WS-LARGO             PIC 9(3) VALUE 50.
       01 WS-INDICE            PIC 9(3).
       01 WS-BYTE              PIC X.
       01 WS-ES-SOSPECHOSO     PIC X VALUE "N".

      *> Test case: clean input
       01 WS-PRUEBA-OK         PIC X(20) VALUE "PAGO-12345".

      *> Test case: U+200B Zero-Width Space (UTF-8: E2 80 8B)
      *> Simulates what a Glassworm-style attack injects
       01 WS-PRUEBA-MAL        PIC X(20).

       PROCEDURE DIVISION.
           DISPLAY "--- COBOL Shield: Invisible Char Auditor ---"
           DISPLAY "Ref: CVE-2021-42574 Trojan Source"
           DISPLAY " "

      *> Test 1: clean
           MOVE WS-PRUEBA-OK TO WS-REGISTRO
           PERFORM AUDITAR-REGISTRO

      *> Test 2: inject zero-width space at byte level
           MOVE "PAGO" TO WS-PRUEBA-MAL
           MOVE X"E2808B" TO WS-PRUEBA-MAL(5:3)
           MOVE "-12345" TO WS-PRUEBA-MAL(8:6)
           MOVE WS-PRUEBA-MAL TO WS-REGISTRO
           PERFORM AUDITAR-REGISTRO

           STOP RUN.

       AUDITAR-REGISTRO.
           MOVE "N" TO WS-ES-SOSPECHOSO
           DISPLAY "Auditando: [" WS-REGISTRO "]"

           PERFORM VARYING WS-INDICE FROM 1 BY 1
               UNTIL WS-INDICE > WS-LARGO

               MOVE WS-REGISTRO(WS-INDICE:1) TO WS-BYTE

      *>         C0 controls: X'00'-X'1F' except TAB/CR/LF
               IF WS-BYTE < X"20"
                   AND WS-BYTE NOT = X"09"
                   AND WS-BYTE NOT = X"0A"
                   AND WS-BYTE NOT = X"0D"
                   MOVE "S" TO WS-ES-SOSPECHOSO
                   DISPLAY "  -> C0 Control en pos " WS-INDICE
                       " HEX=" FUNCTION HEX-OF(WS-BYTE)
               END-IF

      *>         U+200B Zero-Width Space (UTF-8: E2 80 8B)
               IF WS-INDICE <= 48
                   IF WS-REGISTRO(WS-INDICE:3) = X"E2808B"
                       MOVE "S" TO WS-ES-SOSPECHOSO
                       DISPLAY "  -> ZERO-WIDTH SPACE U+200B en pos "
                           WS-INDICE
                   END-IF

      *>         U+202E Bidi Override - Trojan Source vector
                   IF WS-REGISTRO(WS-INDICE:3) = X"E280AE"
                       MOVE "S" TO WS-ES-SOSPECHOSO
                       DISPLAY "  -> BIDI OVERRIDE U+202E en pos "
                           WS-INDICE
                       DISPLAY "     *** TROJAN SOURCE CVE-2021-42574 ***"
                   END-IF
               END-IF

           END-PERFORM

           IF WS-ES-SOSPECHOSO = "S"
               DISPLAY "  RESULTADO: RECHAZADO - Contiene invisibles"
           ELSE
               DISPLAY "  RESULTADO: OK - Limpio"
           END-IF
           DISPLAY " ".
