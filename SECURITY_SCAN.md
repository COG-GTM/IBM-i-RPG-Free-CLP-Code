# Security Scan — RPG / SQLRPGLE / CLP / CLLE / SQL

Repositorio: `COG-GTM/IBM-i-RPG-Free-CLP-Code`
Rama de integración: `security/scan-remediation`
Estado: **informe final** — las cinco áreas de remediación están fusionadas en `security/scan-remediation`.

## 1. Alcance e inventario

Escaneo de todos los fuentes RPG, SQLRPGLE, CLP, CLLE y SQL del repositorio.

| Carpeta | RPGLE | SQLRPGLE | CLP / CLLE | SQL |
|---|---|---|---|---|
| 5250_Subfile | — | LOADCUSTR, MTNCUSTR, PMTCUSTR, PMTSTATER | CRTDTAARA.clle, CRTMSGF, LOADCUST, LOADCUST2 | Custmast, Custmast2, States |
| APIs | GETJOBTR, GETOBJUR, SRTUSRSPC | — | CLERRHANDL, GETOBJUC, LCKOBJC, T0, T1, T2, T9.CLP, T9ALLOC1, T9ALLOCMNY.CLP | GETOBJUP.SQL |
| APIs_SQL | — | GETOBJUR | GETOBJUC, LCKOBJC, LCKOBJCorg, T0, T00, T1, T2, T3, T9ALLOC1, T9ALLOCMNY, T9DSPMNY, t90 | — |
| BASE36 | BASE36_P, BTIR, SRV_BASE36 | BTBR | CRTBNDDIR | — |
| Copy_Mbrs | AIDBYTES, BASE36_P, PRT_P, SRV_MSG_P, SRV_RAND_P, SRV_SQL_P, SRV_STE_P, SRV_STR_P, USADRVALDS, USADRVAL_P, USPHDR | — | — | — |
| DATEADJ | DATEADJR, T1R | — | DATEADJC, T1C, T2C, T3C | — |
| DATE_UDF | DATE_SQL, DATE_SQLFR, DATE_SQLFX | — | — | DATECRTFN, TEST_CYMD, TEST_MDY, TEST_YMD |
| GRP_JOB | — | — | GRP.CLP, GRP_ATN.CLP, GRP_INIT.CLP, GRP_LIBL.CLP | — |
| PGM_REFS | — | — | — | pgm.refs_Tbl, pgm_refs, pgm_refs_test |
| PRT_CL | PRT, PRT_T | DEMO_RPG1 | DEMO_CL1, DEMO_CL2.CLP, DEMO_CL3, MYPRT, PRTLNC, PRTLNCV | — |
| Printing | DEMOFCFC, DEMOPRTCTL | — | — | — |
| RcdLckDsp | RCDLCKBAD, RCDLCKDEMO, RCDLCKDSP | — | — | — |
| SNGCHCFLD | Booth | — | — | — |
| SQL_SKELETON | — | SQL_SKEL2, SQL_SKEL3, sql_skel, sql_skelnf | SQLC, SQLC2 | — |
| Service_Pgms | SHOW, SHOW_T, SRV_MSG, SRV_MSGTL, SRV_MSGTR, SRV_STR, SRV_STRTR, StateV_T | SRV_RANDOM, SRV_RANDT1, SRV_SQL, StateVal | CRTBNDDIR | — |
| USPS_Address | USADRVAL_T | MTNCUSTR, USADRVAL | CRTBNDDIR | — |
| Utils | — | — | QRYC.CLP, RCC.CLLE | — |
| Z_Exp1 | B2R | — | — | — |

## 2. Hallazgos preliminares por severidad

### Severidad ALTA

| ID | Archivo | Línea(s) | Riesgo | Remediación propuesta |
|---|---|---|---|---|
| H-1 | `USPS_Address/USADRVAL.SQLRPGLE` | 74–93 | **Inyección XML**: el documento `AddressValidateRequest` se construye por concatenación con `:pi.Address1`, `:pi.Address2`, `:pi.City`, `:pi.State`, `:pi.Zip5`, `:pi.Zip4`. `url_encode` protege el transporte en la URL pero no escapa el contenido XML: un valor con `<`, `>`, `"`, `&` o `'` rompe o altera el documento (inyección de atributos/elementos). | Escapar entidades XML en todos los valores antes de insertarlos en el documento. |
| H-2 | `USPS_Address/USADRVAL.SQLRPGLE` | 43–46, 63–69, 80–81 | **Credenciales en la URL y riesgo de exposición en trazas**: `USERID`/`PASSWORD` provienen de data areas `USPS_ID`/`USPS_PWD` y viajan dentro del query string; cualquier volcado de sentencia SQL, job log o depuración puede exponerlas. | Escapar también las credenciales, documentar los permisos requeridos sobre las data areas (`*USE` restringido, `*PUBLIC *EXCLUDE`) y asegurar que no se registran en mensajes de error/trazas. |
| H-3 | `PGM_REFS/pgm_refs.sql` | 61–68, 139–140 | **Inyección de comandos CL**: la cadena `DSPPGMREF ...` (y `DLTF ...`) se construye concatenando los parámetros del procedimiento `p_INLIB`, `p_INPGM`, `p_INTYPE` y se ejecuta con `QSYS2.QCMDEXC`. Un valor con `)` permite añadir parámetros o comandos adicionales. | Validar los parámetros como nombres de objeto IBM i (longitud ≤10, juego de caracteres permitido, sin blancos ni separadores) antes de construir el comando; rechazar valores no conformes. |
| H-4 | `PGM_REFS/pgm_refs.sql` | 88–93 | **SQL dinámico**: `prepare ref_cursor_stmt from ref_cursor_txt` sobre un texto que incorpora `WrkFileSQL`, derivado de `WrkLib` y del nivel de recursión. | Validar/cotejar el nombre de biblioteca y fichero de trabajo (identificador SQL válido, biblioteca fija de trabajo como QTEMP) antes del `prepare`. |

### Severidad MEDIA

| ID | Archivo | Línea(s) | Riesgo | Remediación propuesta |
|---|---|---|---|---|
| M-1 | `APIs/LCKOBJC.CLLE`, `APIs_SQL/LCKOBJC.CLLE` | ~120–150 | Comando `ALCOBJ` construido por concatenación (`&OBJLIB`, `&OBJNAM`, `&TYPE`, `&LCKSTATE`, `&MEMBER`, `&WAITC`) y ejecutado con `CALL PGM(QCMDEXC)`. Los valores llegan de la CMD `LCKOBJ` (validada por el sistema), pero el programa también puede llamarse directamente. | Validar los parámetros en el programa (longitud, caracteres válidos, valores de la lista de tipos/estados permitidos) en lugar de confiar solo en la CMD. |
| M-2 | `GRP_JOB/GRP_INIT.CLP` | 34 | `CALL PGM(QCMDEXC) PARM(&GDA 512)` ejecuta el contenido de la *GDA: cualquier usuario con acceso al job de grupo puede colocar allí un comando arbitrario. | Documentar el modelo de confianza y validar/limitar el comando admitido; advertir explícitamente del riesgo. |
| M-3 | `APIs_SQL/GETOBJUC.CLLE`, `APIs/GETOBJUC.CLLE` | 41–47 | El parámetro `&OBJECT` (20 caracteres, objeto+biblioteca) se trocea con `%SST` sin validar contenido antes de usarlo en `RTVOBJD` y de pasarlo a `GETOBJUR`. | Validar que nombre y biblioteca no estén en blanco y sean nombres de objeto válidos; comprobar existencia/autorización antes de operar. |
| M-4 | `5250_Subfile/PMTCUSTR.SQLRPGLE` | 231–252 | El propio código advierte que el programa debería invocarse desde un menú que imponga seguridad; con `%parms() = 0` entra en un modo sin parámetros. | Reforzar la comprobación de parámetros y documentar el requisito de control de acceso del objeto (autoridad `*PUBLIC *EXCLUDE` + perfil adoptado). |

### Severidad BAJA

| ID | Archivo | Línea(s) | Riesgo | Remediación propuesta |
|---|---|---|---|---|
| L-1 | `RcdLckDsp/RCDLCKBAD.RPGLE` | 29, 40 | `QCMDEXC` con cadena **constante** (`OVRDBF ... WAITRCD(1)`): sin entrada de usuario. El programa es un ejemplo didáctico de mal manejo de bloqueos. | Documentar como anti-patrón didáctico, no apto para producción; dejar claro que el uso de QCMDEXC aquí es de bajo riesgo por ser constante. |
| L-2 | `RcdLckDsp/RCDLCKDEMO.RPGLE` | 35, 49 | Igual que L-1: comando constante. | Documentar como bajo riesgo. |
| L-3 | `5250_Subfile/*.SQLRPGLE`, `SQL_SKELETON/*`, `Service_Pgms/*.SQLRPGLE`, `USPS_Address/MTNCUSTR.SQLRPGLE` | — | SQL embebido: en la revisión preliminar toda la entrada de usuario se pasa con variables host (`:var`); no se detecta `PREPARE`/`EXECUTE IMMEDIATE` fuera de `PGM_REFS/pgm_refs.sql`. | Confirmar exhaustivamente y corregir cualquier concatenación insegura que aparezca. |
| L-4 | Global | — | Búsqueda de secretos embebidos: no se encontraron contraseñas ni user ids literales; las credenciales USPS viven en data areas (`USPS_ID`, `USPS_PWD`). | Documentar el procedimiento de aprovisionamiento y los permisos de esas data areas; confirmar que ningún fuente lleva valores reales. |

## 3. Plan de remediación por área

| Área | Sub-rama | Alcance |
|---|---|---|
| A — Inyección XML y credenciales USPS | `security/xml-usadrval` | `USPS_Address/USADRVAL.SQLRPGLE` (+ copy members asociados) |
| B — Inyección de comandos (QCMDEXC) | `security/cmd-injection` | `RcdLckDsp/RCDLCKBAD.RPGLE`, `RcdLckDsp/RCDLCKDEMO.RPGLE`, `APIs/LCKOBJC.CLLE`, `APIs_SQL/LCKOBJC.CLLE`, `GRP_JOB/GRP_INIT.CLP`, `PGM_REFS/pgm_refs.sql` |
| C — Inyección SQL y SQL dinámico | `security/sql-injection` | Todos los fuentes con `EXEC SQL` y `PGM_REFS/pgm_refs.sql` |
| D — Validación de parámetros y control de acceso en CL | `security/param-validation` | `APIs_SQL/GETOBJUC.CLLE`, `APIs/GETOBJUC.CLLE`, `5250_Subfile/PMTCUSTR.SQLRPGLE` |
| E — Secretos hardcodeados | `security/secrets` | Búsqueda global en fuentes y definiciones de data areas |

## 4. Resultado final

| ID | Archivo | Línea(s) | Severidad | Estado | Remediación aplicada | PR |
|---|---|---|---|---|---|---|
| H-1 | `USPS_Address/USADRVAL.SQLRPGLE` | 62–96 (proc `XmlEscape`), 152–177 | ALTA | remediado | Procedimiento local `XmlEscape` que sustituye `&`, `<`, `>`, `"`, `'` por entidades; todos los valores de dirección se escapan antes de construir el documento XML. | [#5](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/5) |
| H-2 | `USPS_Address/USADRVAL.SQLRPGLE` | 16–29, 114–135, 168–177 | ALTA | remediado | Credenciales también escapadas; `clear` de `ID`/`PWD`/`xID`/`xPWD` tras la llamada; cabecera documenta `*PUBLIC *EXCLUDE`, autoridad adoptada y el riesgo de trazas/job log; `USPS_Address/Readme.md` amplía el aprovisionamiento seguro. | [#5](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/5) |
| H-3 | `PGM_REFS/pgm_refs.sql` | 66–110, 138–160 | ALTA | remediado | Copias validadas `v_INLIB`/`v_INPGM`/`v_INTYPE` (trim+upper, no vacías, ≤10, juego de caracteres de nombre IBM i, `*LIBL`/`*CURLIB` admitidos, lista blanca de tipos); si falla se inserta fila de error y `return` sin ejecutar `QSYS2.QCMDEXC`. | [#8](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/8) |
| H-4 | `PGM_REFS/pgm_refs.sql` | 138–158 | ALTA | remediado | Comprobación defensiva del identificador del fichero de trabajo antes del `prepare`; si no es un nombre SQL simple, fila de error y `return`. | [#8](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/8) |
| M-1 | `APIs/LCKOBJC.CLLE`, `APIs_SQL/LCKOBJC.CLLE` | ~120–195 | MEDIA | remediado | Validación en el CPP: nombres no en blanco, caracteres permitidos (`%CHECK`), sin blancos embebidos, `&TYPE` con `*`, `&LCKSTATE` contra la lista de la CMD, `&MEMBER` si viene informado; fallo → etiqueta `BADPARM` con `CPF9898` `*ESCAPE`. Ambos fuentes siguen idénticos. | [#8](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/8) |
| M-2 | `GRP_JOB/GRP_INIT.CLP` | 34–51 | MEDIA | mitigado y documentado | Se comprueba que la *GDA no esté en blanco antes de ejecutarla; modelo de confianza documentado en la cabecera y en `GRP_JOB/ReadMe.md` (uso solo en el job propio, sin autoridad adoptada, no reutilizar con entrada no confiable). | [#8](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/8) |
| M-3 | `APIs/GETOBJUC.CLLE`, `APIs_SQL/GETOBJUC.CLLE` | 41–150 | MEDIA | remediado | Validación de nombre/biblioteca (`%CHECK`/`%CHECKR`), tipo contra lista, miembro obligatorio si `*FILE`, y `CHKOBJ ... AUT(*USE)` con `MONMSG` antes de `RTVOBJD`; errores por etiqueta `PARMERR` con `CPF9898`. | [#9](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/9) |
| M-4 | `5250_Subfile/PMTCUSTR.SQLRPGLE` | 231–275 | MEDIA | remediado | Rechazo de `%parms()` excedente, de `pParmType` fuera de S/M/I y del modo `S` sin parámetro de retorno, con `snd-msg *DIAG` + `*ESCAPE`; control de acceso (`*PUBLIC *EXCLUDE`, `USRPRF(*OWNER)`) documentado en la cabecera y en `5250_Subfile/README.md`. | [#9](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/9) |
| L-1 | `RcdLckDsp/RCDLCKBAD.RPGLE` | 29, 40 | BAJA | documentado | Sin cambios de lógica: cabecera marca la cadena como constante (bajo riesgo) y el programa como anti-patrón didáctico no apto para producción; nota también en `RcdLckDsp/Readme.md`. | [#8](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/8) |
| L-2 | `RcdLckDsp/RCDLCKDEMO.RPGLE` | 35, 49 | BAJA | documentado | Nota de seguridad en la cabecera: cadena constante, nunca construir el comando con datos de usuario. | [#8](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/8) |
| L-3 | Fuentes con `EXEC SQL` (`5250_Subfile`, `SQL_SKELETON`, `Service_Pgms`, `USPS_Address/MTNCUSTR`) | — | BAJA | confirmado / remediado | Revisión completa: toda la entrada de usuario usa variables host; no hay `PREPARE`/`EXECUTE IMMEDIATE` fuera de `PGM_REFS/pgm_refs.sql`. Se añadieron notas de uso de variables host y se condicionó el `DUMP(A)` de `Service_Pgms/SRV_SQL.SQLRPGLE` a una variable de entorno explícita para no volcar datos sensibles. | [#7](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/7) |
| L-4 | Global | — | BAJA / INFO | documentado | No hay secretos literales en los fuentes; las credenciales USPS viven en data areas. Nuevo `docs/SECRETS_MANAGEMENT.md` (enlazado desde el README) con aprovisionamiento, autoridades `*PUBLIC *EXCLUDE`, perfiles adoptados, rotación, no exposición en job logs/spool/depuración y checklist de revisión. | [#6](https://github.com/COG-GTM/IBM-i-RPG-Free-CLP-Code/pull/6) |

## 5. Verificación

Se ejecutaron 77 comprobaciones (todas superadas): estáticas sobre los fuentes fusionados (presencia y **orden** de cada control, ausencia de los patrones inseguros originales, consistencia entre copias duplicadas, barrido de secretos) y puertos ejecutables de la lógica añadida (`XmlEscape` del RPG, el bloque `translate`/`locate` del SQL PL, y `%CHECK`/`%CHECKR`/`%SCAN` del CL) contra cargas útiles de inyección y entradas legítimas.

Defecto detectado por esa ejecución y corregido: en `PGM_REFS/pgm_refs.sql`, `trim(translate(...))` no rechazaba un blanco embebido (`translate` convierte los caracteres permitidos en blancos y el `trim` elimina también el original), por lo que `'A B'` llegaba concatenado a `DSPPGMREF PGM(lib/A B)`. Se añadió `locate(' ', v_INLIB) > 0` y `locate(' ', v_INPGM) > 0`. Los paréntesis y demás caracteres no permitidos sí quedaban bloqueados desde el principio.

- Las cinco sub-ramas se fusionaron en `security/scan-remediation` sin conflictos.
- `APIs/LCKOBJC.CLLE` y `APIs_SQL/LCKOBJC.CLLE` siguen siendo byte a byte idénticos tras la remediación.
- Búsqueda posterior: el único `PREPARE` del repositorio sigue siendo el de `PGM_REFS/pgm_refs.sql`, ahora precedido de validación; no hay `EXECUTE IMMEDIATE`.
- **No hay compilador IBM i disponible**: RPG free-form, CL y SQL PL se revisaron manualmente; no se compiló ni ejecutó nada. El repositorio no tiene lint, tests ni pipeline de build.
