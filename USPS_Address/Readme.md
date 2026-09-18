# USPS_Address - QSYS2.HTTP_GET calling the US Post Office webtools API AddressValidateRequest

USADRVAL is a service program in RPG Free which uses the QSYS2.HTTP_GET SQL function to call the USPS AddressValidateRequest API. The API returns a validated and standarized address (or an error) in an XML document, which is then parsed with the SQL XMLPARSE function and returned to the caller.

To use the USADRVAL you need to obtain a User Id from the US Post Office. [Follow link here](https://www.usps.com/business/web-tools-apis/general-api-developer-guide.htm#_Toc24631952) to register for a free User Id,

## Credentials

The User Id and password are read from the `USPS_ID` and `USPS_PWD` data areas. Never put real values in the source code, in a CL that is kept in source control, or in a job's environment.

Create the data areas and lock them down:

```
CRTDTAARA DTAARA(USPS_ID)  TYPE(*CHAR) LEN(20) VALUE('your user id')
CRTDTAARA DTAARA(USPS_PWD) TYPE(*CHAR) LEN(20) VALUE('your password')
GRTOBJAUT OBJ(USPS_ID)  OBJTYPE(*DTAARA) USER(*PUBLIC) AUT(*EXCLUDE)
GRTOBJAUT OBJ(USPS_PWD) OBJTYPE(*DTAARA) USER(*PUBLIC) AUT(*EXCLUDE)
GRTOBJAUT OBJ(USPS_ID)  OBJTYPE(*DTAARA) USER(APPOWNER) AUT(*USE)
GRTOBJAUT OBJ(USPS_PWD) OBJTYPE(*DTAARA) USER(APPOWNER) AUT(*USE)
```

Let `APPOWNER` (the application profile) own the service program and create it with `USRPRF(*OWNER)` so that end users reach the data areas only through adopted authority.

The USPS API takes the credentials in the query string, so they can end up in job logs, SQL traces and program dumps. USADRVAL clears both values from memory immediately after the API call and passes only a generic text to `SQLProblem`, but you should still avoid running the service program with debug or SQL tracing active (`STRDBG`, SQL trace, job logging level 4), and rotate the credentials if a dump or trace with the request ever leaves the system.

## XML escaping

The request document is built by concatenation, so every value that goes into it (address fields and credentials alike) is passed through the local `XmlEscape` procedure, which replaces `&`, `<`, `>`, `"` and `'` with their entity references. Without it an address containing, say, `Smith & Sons "A"` would break the document or let a caller inject elements or attributes.

Included is a demo interactive program which is a rewritten version of MNTCUSTR in the [5250_Subfile](https://github.com/SJLennon/IBM-i-RPG-Free-CLP-Code/tree/master/5250_Subfile) directory.

## CRTBNDDIR.CLLE

Simple program to create the ADRVAL binding directory.

### MTNCUSTR/MTNCUSTD

Demo program and display file to maintain a customer master. To use the program you must compile the objects in the [5250_Subfile](https://github.com/SJLennon/IBM-i-RPG-Free-CLP-Code/tree/master/5250_Subfile) directory, then compile these two objects.

This program uses a single address line, which is passed as ADDRESS2 to the API. If you decide to use an additional address line, pass it in ADDRESS1.

(This program needs some additional coding to allow you to ignore the USPS standardized address.)

### USADRVAL

The service program.

Input address and output address are passed in the USADRVALDS data structure, which is found in [Copy_Mbrs](https://github.com/SJLennon/IBM-i-RPG-Free-CLP-Code/tree/master/Copy_Mbrs)

A call looks like this:

 ``returned address  = USAdrVal(input address);``

If ADDRESS2 is non blank, then you have a valid address.  Otherwise find a description of the problem in the DESCRIPTION field.

### USADRVAL_T

A program to exercise USADRVAL with some addresses, writing the input and output side by side to QSYSPRT.
