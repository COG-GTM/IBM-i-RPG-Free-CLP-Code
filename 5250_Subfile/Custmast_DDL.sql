 -- Create CUSTMAST & Indexs and load 300 records -----------
 -- Program LOADCUST submits this to batch.
 -- Or you can run it interactively in iACS Run SQL Scripts

 -- 02/2024 Change CustID to char to allow alpha/numeric keys

 set schema lennons1;  -- <<<<< Change to your library <<<<<<
 DROP TABLE custmast;

-- 02/2024 Change CUSTID to char to allow alpha-numeric key

CREATE TABLE custmast (
    CustID CHAR(4) NOT NULL
    ,Name CHAR(40) NOT NULL
    ,Addr CHAR(40) NOT NULL
    ,City CHAR(20) NOT NULL
    ,State CHAR(2) NOT NULL
    ,Zip CHAR(10) NOT NULL
    ,CorpPhone CHAR(20) DEFAULT ' '
    ,AcctMgr CHAR(40) DEFAULT ' '
    ,AcctPhone CHAR(20) DEFAULT ' '
    ,Active CHAR(1) DEFAULT 'Y'
,PRIMARY KEY (Custid)
)
RCDFMT CUSTMASTF;
