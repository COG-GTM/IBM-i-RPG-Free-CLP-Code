# Gestión de secretos y credenciales (IBM i)

Documento del área **E — Secretos hardcodeados y gestión de credenciales** del escaneo de
seguridad del repositorio. Recoge el resultado de la búsqueda de secretos embebidos y la guía
de cómo deben gestionarse las credenciales en este código.

---

## 1. Resultado de la búsqueda de secretos

### 1.1 Alcance

Búsqueda global sobre **todo** el repositorio (no solo los fuentes del área): RPGLE, SQLRPGLE,
CLP, CLLE, SQL, CMD, PNLGRP, DSPF, ficheros Markdown y el historial de commits alcanzable
(`git log -S`, clon completo, no superficial).

### 1.2 Patrones buscados

- Credenciales por nombre: `password`, `passwd`, `pwd`, `userid`, `user id`, `secret`,
  `credential`, `token`, `api key` / `apikey`, `auth`, `login`.
- Definición y uso de data areas: `CRTDTAARA`, `CHGDTAARA`, `RTVDTAARA`, `dtaara(...)`,
  `VALUE(...)` (para detectar valores literales asignados al crear/cambiar un data area).
- Perfiles y comandos sensibles de IBM i: `USRPRF`, `USER(`, `PASSWORD(`, `PWD(`, `QSECOFR`,
  `QPGMR`, `SBMJOB ... USER(...)`.
- Cadenas de conexión y material criptográfico: `CONNECT TO`, `jdbc:`, `ftp://`,
  `http(s)://usuario:clave@host`, `-----BEGIN ... PRIVATE KEY-----`, `Bearer `, `Basic <b64>`,
  claves de acceso tipo `AKIA...`, y cadenas largas en base64.
- Revisión del historial reciente en busca de valores eliminados (`git log -p -S"PASSWORD"`,
  historial completo de `USPS_Address/`).

### 1.3 Conclusión

**No se encontró ningún secreto real (contraseña, token, clave de API o cadena de conexión con
credenciales) embebido en el código ni en la documentación, ni en el historial revisado.**

Se confirma el hallazgo preliminar de la sesión padre: las credenciales de la API de USPS se leen
en tiempo de ejecución desde las data areas `USPS_ID` y `USPS_PWD`, y el código **no** contiene
valores literales. El comentario de cabecera

```
// CRTDTAARA DTAARA(USPS_ID) TYPE(*CHAR) LEN(20) VALUE(your user id)
```

(`USPS_Address/USADRVAL.SQLRPGLE`, línea 15) es un **marcador de posición**, no un secreto.

### 1.4 Observaciones (sin secretos, pero relevantes)

| # | Archivo | Línea(s) | Tipo | Riesgo | Tratamiento |
|---|---|---|---|---|---|
| E-1 | `USPS_Address/USADRVAL.SQLRPGLE` | 15 | Ejemplo `CRTDTAARA ... VALUE(your user id)` | Ninguno: valor de ejemplo. Nota: solo se documenta la creación de `USPS_ID`; falta el ejemplo equivalente para `USPS_PWD`, que el programa sí lee (líneas 45, 68-69). | Documentado. El archivo está fuera del permiso de edición de esta rama (área USPS); se deja para la sesión propietaria. |
| E-2 | `USPS_Address/USADRVAL.SQLRPGLE` | 63-69, 80-81 | `USERID=`/`PASSWORD=` viajan en el query string de `QSYS2.HTTP_GET` | Exposición de credenciales en job logs, trazas SQL, spooled files o volcados de depuración. | Documentado aquí (sección 4). Remediación de código a cargo del área USPS (hallazgo H-2 del informe padre). |
| E-3 | `GRP_JOB/GRP.CLP` (8), `GRP_JOB/GRP_LIBL.CLP` (7), `APIs_SQL/T2.CLLE` (7), `APIs_SQL/T9ALLOC1.CLLE` (5), `Service_Pgms/SRV_RANDOM.SQLRPGLE` (19), `Service_Pgms/SRV_RANDT1.SQLRPGLE` (16-21), `Service_Pgms/StateVal.sqlrpgle` (9) | varias | Nombres de biblioteca/perfil del desarrollador embebidos (`LENNONS1`, `LENNONS2`) | **Bajo**. No son secretos: son nombres de biblioteca de un entorno de desarrollo público (PUB400). Sí acoplan el código a ese entorno y revelan la convención de nombres del perfil. | No se modifica (cambio funcional fuera de alcance). Recomendación: parametrizar la biblioteca o usar `*LIBL`/`*CURLIB` al adaptar el código. |
| E-4 | `Service_Pgms/SRV_MSGTD.DSPF`, `APIs_SQL/LCKOBJCorg.CLLE`, cabeceras varias | varias | Identificadores de usuario en sellos de SEU/DDS y comentarios (`LENNON`, `SLENNON`) | **Informativo**. Metadatos históricos del fuente. | No se modifica. |
| E-5 | `Service_Pgms/SHOW_T.RPGLE` (18), `Service_Pgms/SRV_MSGTL.RPGLE` (19), `BASE36/SRV_BASE36.RPGLE` (38-39), `5250_Subfile/LOADCUSTR.SQLRPGLE` (224) | varias | Cadenas largas alfanuméricas detectadas por los patrones de alta entropía | **Ninguno**. Son reglas de escala para pruebas y tablas de traducción de caracteres, no claves. | Falso positivo, descartado. |

No hay ningún secreto pendiente de asignar a otra sesión: los archivos fuera del permiso de
edición de esta rama (E-1, E-2) contienen únicamente marcadores de posición y el flujo de uso de
las credenciales, no valores reales.

---

## 2. Cómo deben gestionarse las credenciales en este repositorio

### 2.1 Principio

**Ningún valor real de credencial debe aparecer nunca en el fuente**, tampoco en los comentarios
de ejemplo. El fuente vive en Git (y en el IFS), se comparte, se copia a entornos de prueba y se
publica; cualquier valor escrito ahí se considera comprometido de forma permanente y debe
rotarse. Los ejemplos de comandos deben usar siempre marcadores del tipo
`VALUE('<your user id>')`.

El patrón adoptado en el repositorio es correcto: **el programa lee la credencial en tiempo de
ejecución desde un objeto del sistema** (data area), protegido por la seguridad de objetos de
IBM i.

### 2.2 Aprovisionamiento con data areas

Crear el data area en la biblioteca de la aplicación (nunca en `QGPL` ni en `QTEMP`):

```
CRTDTAARA  DTAARA(APPLIB/USPS_ID)  TYPE(*CHAR) LEN(20) TEXT('USPS Webtools user id')
CRTDTAARA  DTAARA(APPLIB/USPS_PWD) TYPE(*CHAR) LEN(20) TEXT('USPS Webtools password')
```

Y cargar el valor **fuera del fuente**, de forma interactiva o desde un script que no se versiona:

```
CHGDTAARA  DTAARA(APPLIB/USPS_ID)  VALUE('<valor real>')
CHGDTAARA  DTAARA(APPLIB/USPS_PWD) VALUE('<valor real>')
```

Si la instalación dispone de un almacén de credenciales corporativo (por ejemplo, un vault
externo, DCM para certificados, o `QSYS2.SET_SERVER_SBS_ROUTING`/validation lists para casos de
autenticación), úsese ese mecanismo en lugar del data area; el data area es el mínimo aceptable,
no el ideal.

### 2.3 Restricción de autoridad (obligatorio)

Un data area con una credencial debe ser ilegible para `*PUBLIC`:

```
GRTOBJAUT  OBJ(APPLIB/USPS_PWD) OBJTYPE(*DTAARA) USER(*PUBLIC) AUT(*EXCLUDE)
GRTOBJAUT  OBJ(APPLIB/USPS_PWD) OBJTYPE(*DTAARA) USER(APPOWNER) AUT(*USE)
```

- `*EXCLUDE` para `*PUBLIC`, autoridad explícita `*USE` solo para el perfil propietario de la
  aplicación (y, si procede, para el perfil del trabajo por lotes que la ejecuta).
- Repetir para `USPS_ID`: el user id también es una credencial parcial.
- Comprobar además la autoridad de la **biblioteca** que los contiene: `*PUBLIC *EXCLUDE` sobre
  el objeto no basta si la biblioteca permite listar y copiar objetos con autoridad heredada.
- Verificación: `DSPOBJAUT OBJ(APPLIB/USPS_PWD) OBJTYPE(*DTAARA)`.

### 2.4 Perfil adoptado

Para que los usuarios finales puedan ejecutar el programa sin tener autoridad directa sobre el
data area, el programa debe adoptar la autoridad de su propietario:

```
CRTBNDRPG  PGM(APPLIB/USADRVAL) USRPRF(*OWNER) USEADPAUT(*NO)
CHGPGM     PGM(APPLIB/USADRVAL) USRPRF(*OWNER)
```

Reglas:

- El propietario debe ser un **perfil de aplicación sin contraseña**
  (`CRTUSRPRF ... PASSWORD(*NONE)`), nunca `QSECOFR` ni un perfil con `*ALLOBJ`.
- `USEADPAUT(*NO)` en los programas que no deban propagar la autoridad adoptada hacia abajo.
- La autoridad adoptada no se propaga a programas ILE de servicio llamados en otro grupo de
  activación con `ACTGRP` distinto: verificar el encadenamiento real antes de asumir que funciona.
- Adoptar la autoridad mínima: el perfil propietario solo necesita `*USE` sobre el data area.

### 2.5 Por qué no valen las alternativas habituales

- **Literal en el fuente / en un comentario**: queda en Git y en todas las copias del IFS.
- **Variable de entorno del trabajo (`ADDENVVAR`)**: visible con `WRKENVVAR` y en el volcado del
  trabajo.
- **Parámetro de un comando o de `SBMJOB`**: queda en el job log y en `WRKSBMJOB`/`DSPJOB`.
- **Fichero físico sin restricción de autoridad**: cualquier consulta SQL ad hoc lo lee.

---

## 3. Rotación

- Rotar las credenciales de la API en un ciclo definido (recomendado: **cada 90 días**) y de
  inmediato cuando: alguien con acceso deja el equipo, se sospecha de una exposición en un job log
  o spooled file, o el valor se ha escrito alguna vez en un fuente versionado.
- La rotación se hace con `CHGDTAARA` sin recompilar: el programa lee el valor en cada llamada
  (`in USPS_ID`), por lo que no hay que reiniciar los trabajos salvo que la aplicación cachee el
  valor en un grupo de activación de larga duración.
- Registrar fecha de rotación y responsable fuera del repositorio.
- Si un secreto llega a commitearse: rotarlo **primero**, y solo después limpiar el historial.
  Borrar el commit no invalida el valor.

## 4. No exponer credenciales en logs, spooled files ni trazas

Aplica especialmente al patrón de `USADRVAL`, donde la credencial forma parte de la URL enviada a
`QSYS2.HTTP_GET`:

- **Nunca** concatenar la credencial en un mensaje de error, en `SQLProblem()`, en `DSPLY`, ni en
  un `SNDPGMMSG`. Al registrar un fallo de la llamada HTTP, registrar el código de estado y la
  operación, no la sentencia SQL completa ni la URL.
- Evitar `STRDBG`/`STRSQL` con trazas sobre programas que manejan credenciales en entornos con
  datos reales; las trazas SQL (`STRTRC`, `Debug` de Code for IBM i) capturan el texto de la
  sentencia con los valores de las variables host.
- Evitar volcar la URL o el XML de petición a un spooled file de depuración. Si se necesita
  depurar, sustituir el valor por `********` antes de imprimir.
- Revisar la retención de los job logs (`LOG(4 00 *SECLVL)` en trabajos que manejen secretos es
  peligroso) y la autoridad sobre las colas de salida donde acaban los spooled files.
- Preferir credenciales en cabeceras HTTP sobre credenciales en el query string cuando la API lo
  permita: el query string se registra en los logs de los proxies y servidores intermedios.

---

## 5. Checklist para revisores de PR

Antes de aprobar un PR que toque este repositorio:

- [ ] El diff no introduce ninguna contraseña, user id, token, clave de API ni cadena de conexión
      literal, tampoco en comentarios, ejemplos o ficheros de prueba.
- [ ] Los ejemplos de `CRTDTAARA`/`CHGDTAARA` en comentarios usan marcadores
      (`VALUE('<your user id>')`), nunca valores plausibles.
- [ ] Toda credencial nueva se lee de un data area (o del vault de la instalación), no de un
      literal, una variable de entorno ni un parámetro de comando.
- [ ] Todo data area de credenciales nuevo lleva documentado su `GRTOBJAUT ... USER(*PUBLIC)
      AUT(*EXCLUDE)` y la autoridad explícita al perfil de la aplicación.
- [ ] Los programas que leen credenciales se crean con `USRPRF(*OWNER)` y el propietario es un
      perfil de aplicación sin contraseña y sin `*ALLOBJ`.
- [ ] Ningún mensaje de error, `SQLProblem`, `DSPLY`, `SNDPGMMSG` ni salida impresa incluye el
      valor de una credencial ni la URL/sentencia completa que la contiene.
- [ ] No se añaden nombres de biblioteca, perfiles de usuario ni rutas del IFS específicos de un
      entorno donde debería usarse `*LIBL`, `*CURLIB` o un parámetro.
- [ ] Si el PR corrige una exposición de credencial: la credencial afectada ya ha sido **rotada**.
