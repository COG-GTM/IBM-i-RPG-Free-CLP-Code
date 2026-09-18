**free
//==============================================================
//=== USADRVAL: Service program to validate and standardize
//=== a USA address.
//=== Calls the USPS webtools API AddressValidateRequest.
//====================================================================
// See US Postal Service documentation:
// www.usps.com/business/web-tools-apis/address-information-api.htm#_Toc39492052
// www.usps.com/business/web-tools-apis/general-api-developer-guide.htm
//====================================================================
// CRTRPGMOD MODULE(USADRVAL)
// CRTSRVPGM SRVPGM(USADRVAL) EXPORT(*ALL)
// CRTBNDDIR BNDDIR(ADRVAL_BND) TEXT('Address Validation Binding Dir')
// ADDBNDDIRE BNDDIR(ADRVAL_BND) OBJ((USADRVAL *SRVPGM *DEFER))
// CRTDTAARA DTAARA(USPS_ID) TYPE(*CHAR) LEN(20) VALUE(your user id)
// CRTDTAARA DTAARA(USPS_PWD) TYPE(*CHAR) LEN(20) VALUE(your password)
//====================================================================
// Securing the credential data areas:
//   Never store the real USPS user id or password in source code.
//   Keep them only in the data areas, and restrict access to them:
//     GRTOBJAUT OBJ(USPS_ID) OBJTYPE(*DTAARA) USER(*PUBLIC) AUT(*EXCLUDE)
//     GRTOBJAUT OBJ(USPS_PWD) OBJTYPE(*DTAARA) USER(*PUBLIC) AUT(*EXCLUDE)
//     GRTOBJAUT OBJ(USPS_ID) OBJTYPE(*DTAARA) USER(APPOWNER) AUT(*USE)
//     GRTOBJAUT OBJ(USPS_PWD) OBJTYPE(*DTAARA) USER(APPOWNER) AUT(*USE)
//   Callers reach the data areas through adopted authority
//   (CRTSRVPGM ... USRPRF(*OWNER) with APPOWNER owning the objects).
//   The credentials travel in the API query string, so avoid logging
//   or tracing the SQL statement (STRDBG, STRSQL trace, job log
//   level 4) while this service program runs.
//====================================================================
// Input address information is passed in a data structure.
// The standardized address is returned, also in a data structure.
// For ease of use, the same data structure layout is used for
// input and output, but it doesn't have to be the same memory
// in the caller. Use copy member USAdrValDS.
//====================================================================
// 04/2024 LENNON
//  Change to HTTPS
//  Provide password, even though it currently seems to be ignored. 
//====================================================================

ctl-opt
    nomain
    bnddir('SQL_BND')
    option(*nodebugio: *srcstmt)
;
//=== Prototypes =====================================================
/copy ../Copy_Mbrs/SRV_SQL_P.RPGLE

//=== Parameter Data Structure Template ==============================
/copy ../Copy_Mbrs/USADRVALDS.RPGLE

// === Data area containing your USPS supplied User id. ==============
// (The USPS supplied USER ID length is not clear, so I made it
// longer than the 12-char one supplied to me..)
// Ditto for password, though password seems to be ignored.
dcl-ds USPS_ID    dtaara  len(20) qualified;
end-ds;
dcl-ds USPS_PWD   dtaara  len(20) qualified;
end-ds;

//=== XmlEscape ======================================================
//=== Replace the five XML predefined characters with their entity
//=== references so that caller supplied data cannot change the
//=== structure of the request document. Each character is examined
//=== once, so the '&' of an inserted entity is never escaped again.
//=== One character can expand to six, hence the returned length.
dcl-proc XmlEscape;
  dcl-pi XmlEscape varchar(3072);
    piText      varchar(512) const;
  end-pi;

  dcl-s wkText    varchar(3072);
  dcl-s wkChar    char(1);
  dcl-s i         int(10);

  wkText = '';
  for i = 1 to %len(piText);
    wkChar = %subst(piText: i: 1);
    select;
      when wkChar = '&';
        wkText += '&amp;';
      when wkChar = '<';
        wkText += '&lt;';
      when wkChar = '>';
        wkText += '&gt;';
      when wkChar = '"';
        wkText += '&quot;';
      when wkChar = '''';
        wkText += '&apos;';
      other;
        wkText += wkChar;
    endsl;
  endfor;

  return wkText;

end-proc XmlEscape;

//=== USAdrVal =======================================================
dcl-proc USAdrVal   export;
  dcl-pi USAdrVal likeds(USAdrValDS);
    pi likeds   (USAdrValDS);
  end-pi;

  dcl-c SQLSUCCESS       '00000';
  dcl-c SQLNODATA        '02000';

  // XML returned from the USPS API
  dcl-s retXML     char(2048) ccsid(*UTF8);

  // Returned outparm data structure
  dcl-ds  po  likeds(USAdrValDS);

  dcl-s ID        varchar(20);
  dcl-s PWD       varchar(20);

  // XML escaped values actually sent to the API. They are longer
  // than their sources because escaping expands the text.
  dcl-s xID       varchar(120);
  dcl-s xPWD      varchar(120);
  dcl-s xAddress1 varchar(180);
  dcl-s xAddress2 varchar(180);
  dcl-s xCity     varchar(180);
  dcl-s xState    varchar(12);
  dcl-s xZip5     varchar(30);
  dcl-s xZip4     varchar(24);

  // Get USPS UserID & Password
  in USPS_ID;
  ID = %trim(USPS_ID);
  in USPS_PWD;
  PWD = %trim(USPS_PWD);

  // Escape everything placed in the XML document, including the
  // credentials, so that no value can inject elements or attributes.
  xID       = XmlEscape(ID);
  xPWD      = XmlEscape(PWD);
  xAddress1 = XmlEscape(%trimr(pi.Address1));
  xAddress2 = XmlEscape(%trimr(pi.Address2));
  xCity     = XmlEscape(%trimr(pi.City));
  xState    = XmlEscape(%trimr(pi.State));
  xZip5     = XmlEscape(%trimr(pi.Zip5));
  xZip4     = XmlEscape(%trimr(pi.Zip4));

  clear po;

  // Call USPS Address Validate API. It returns an XML document.
  exec sql
    values  QSYS2.HTTP_GET(
      'https://secure.shippingapis.com/ShippingAPI.dll'
      concat '?API=Verify&XML=' concat
      url_encode(
        '<AddressValidateRequest ' concat
        'USERID="' concat :xID concat '"' 
          concat ' PASSWORD="' concat :xPWD concat '">' concat
        '<Revision>1</Revision>' concat
        '<Address ID="0">' concat
            '<Address1>' concat :xAddress1 concat '</Address1>' concat
            '<Address2>' concat :xAddress2 concat '</Address2>' concat
            '<City>' concat :xCity concat '</City>' concat
            '<State>' concat :xState concat '</State>' concat
            '<Zip5>' concat :xZip5 concat  '</Zip5>' concat
            '<Zip4>' concat :xZip4 concat '</Zip4>' concat
        '</Address>' concat
        '</AddressValidateRequest>'
      )
    ) into :retXML;

  // Drop the credentials as soon as the call is made. SQLProblem
  // issues DUMP(A), so they must not still be in memory, and the
  // debug text passed to it never contains the URL or the statement.
  clear PWD;
  clear xPWD;
  clear ID;
  clear xID;

  if (SQLSTATE <> SQLSUCCESS);
    SQLProblem('USPS API Call');
  endif;

  // Parse the XML document into program variables. Even if the API
  // returns an error the SQL should not fail since defaults are set
  exec sql
    select x.* into :po.Address1, :po.Address2, :po.City,
                    :po.State, :po.Zip5, :po.Zip4
    from xmltable
    ('AddressValidateResponse/Address'
        passing xmlparse(document  :retXML)
        columns
            Address1    char(30)    path 'Address1' default ' ',
            Address2    char(30)    path 'Address2' default ' ',
            City        Char(30)    path 'City' default ' ',
            State       char(2)     path 'State' default ' ',
            zip5        char(5)     path 'Zip5' default ' ',
            Zip4        char(4)     path 'Zip4' default ' '
    ) as x;
  if (SQLSTATE <> SQLSUCCESS);
    SQLProblem('XMLPARSE of Addr');
  endif;

  //  If a city was returned, assume it worked.
  if (po.City <> ' ');
    return po;
  endif;

  // If no city, then parse the error XML
  exec SQL
    select x.* into :po.Number, :po.Source, :po.Description
    from xmltable
    ('AddressValidateResponse/Address/Error'
        passing xmlparse(document  :retXML)
        columns
            Number      integer         path 'Number',
            Source      char(30)        path 'Source',
            Description varChar(512)    path 'Description'
    ) as x;
  if (SQLSTATE <> SQLSUCCESS);
    SQLProblem('XMLPARSE of Error');
  endif;
  return po;

end-proc USAdrVal;
