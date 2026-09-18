# Security Scan — RPG / SQLRPGLE / CLP / CLLE / SQL

Repositorio: `COG-GTM/IBM-i-RPG-Free-CLP-Code`
Rama de integración: `security/scan-remediation`
Estado: **informe inicial (Fase 0)** — se actualiza con el resultado final tras fusionar las remediaciones por área.

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

Pendiente: se completa en la consolidación con el estado de cada hallazgo (remediado / mitigado / documentado) y los enlaces a los PR intermedios por área.
