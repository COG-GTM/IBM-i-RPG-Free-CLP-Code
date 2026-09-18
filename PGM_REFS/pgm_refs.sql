--  Procedure to run DPSPGMREF, then run DSPPGMREF on each of its objects
--  by calling itself recursively.
--  Result is a file named REFS containing all the objects that 
--  DSPPGMREF knows about an object, to an essentially unlimited depth.

-- There are two places you need to change the library name, following
-- a comment like this:  -- <<<<<< Change this table library >>>>>>>

CREATE OR REPLACE PROCEDURE PGM_REFS (
     IN p_INLIB     varCHAR(10)
    ,IN p_INPGM     varCHAR(10)
    ,IN p_INTYPE    varCHAR(10) default '*PGM'
    ,in p_Depth     integer     default(0)
    )
    LANGUAGE SQL
    NOT DETERMINISTIC
    MODIFIES SQL DATA
    SET OPTION dbgview = *source, commit = *none
begin
    -- Define DSPPGMREF OUTFILE library and file names
    declare WrkLib          varchar(10) default 'QTEMP'; 
    declare WrkFileOS       varchar(20) default '/WRK' ;
    declare WrkFileSQL      varchar(20) default '.WRK';

    declare sqlstate        char(5);
    declare my_sqlstate     char(5);
    declare no_more_data    char(5) default '02000';
    declare duplicate_key   char(5) default '23505';
    declare error_msg        char(30) default ' ';
    declare Cmd             varchar(1024);

    -- Validated (trimmed, upper cased) copies of the parameters.
    -- Only these are concatenated into the CL command string.
    declare v_INLIB         varchar(10) default ' ';
    declare v_INPGM         varchar(10) default ' ';
    declare v_INTYPE        varchar(10) default ' ';
    -- Character set allowed in an IBM i object name.
    declare name_chars      varchar(50) default
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@_.';
    declare ref_cursor_txt  varchar(512) default  
        'select WHLIB, WHPNAM, WHTEXT, WHLNAM, WHFNAM, WHOTYP 
        from ' ;

    -- Our cross ref fields for the REFS file
    declare CALLER_LIBRARY varchar(10);
    declare CALLER_NAME    varchar(10);
    declare CALLER_TYPE    varchar(10);
    declare CALLER_TEXT    varchar(30);
    declare USES_LIBRARY   varchar(10);
    declare USES_NAME      varchar(10);
    declare USES_TYPE      varchar(10);

    declare duplicate_object condition for sqlstate '23505';
    declare QCMDEXC_Failure condition for sqlstate '38501';
    declare ref_cursor cursor for ref_cursor_stmt;

    declare continue handler for duplicate_object
        begin
            set my_sqlstate = duplicate_key;
        end;            
    declare continue handler for QCMDEXC_Failure
        begin
            set error_msg = 'QCMDEXC DSPPGMREF Failed';
        end;            
      
    -- Validate the parameters before they are concatenated into a
    -- CL command string and run by QSYS2.QCMDEXC. QCMDEXC runs
    -- whatever it is given, so a value containing a blank or a
    -- parenthesis could add parameters or further commands.
    -- translate() maps the allowed characters to blanks, so an
    -- embedded blank would survive the trim: it is rejected on
    -- its own with locate().
    set v_INLIB  = upper(trim(coalesce(p_INLIB , '')));
    set v_INPGM  = upper(trim(coalesce(p_INPGM , '')));
    set v_INTYPE = upper(trim(coalesce(p_INTYPE, '')));

    if v_INLIB = '' or length(v_INLIB) > 10
        or locate(' ', v_INLIB) > 0
        or (v_INLIB not in ('*LIBL', '*CURLIB')
            and trim(translate(v_INLIB,
                repeat(' ', length(name_chars)), name_chars)) <> '')
    then
        set error_msg = 'Invalid library name';
    elseif v_INPGM = '' or length(v_INPGM) > 10
        or locate(' ', v_INPGM) > 0
        or trim(translate(v_INPGM,
            repeat(' ', length(name_chars)), name_chars)) <> ''
    then
        set error_msg = 'Invalid object name';
    elseif v_INTYPE not in
        ( '*PGM', '*SRVPGM', '*MODULE', '*QRYDFN', '*SQLPKG') then
        set error_msg = 'Invalid object type';
    end if;

    if error_msg <> ' ' then
        -- The REFS columns are NOT NULL, so report the normalised
        -- values: a null or blank parameter is logged as *BLANK.
        -- <<<<<< Change this table library >>>>>>>
        insert into lennonsb.refs values (
            p_Depth,
            coalesce(nullif(v_INLIB , ''), '*BLANK'),
            coalesce(nullif(v_INPGM , ''), '*BLANK'),
            coalesce(nullif(v_INTYPE, ''), '*BLANK'),
            error_msg,
            '*ERROR',
            '*ERROR',
            '*ERROR'
        );
        set error_msg = ' ';
        return;
    end if;

    -- Build pgm refs work file from DSPPGMREF command.
    set WrkFileOS = WrkLib 
        concat trim(WrkFileOS) 
        concat trim(char(p_Depth));
    set Cmd ='DSPPGMREF PGM(' 
        concat v_INLIB 
        concat '/' concat v_INPGM concat ')'
        concat ' OBJTYPE(' concat v_INTYPE CONCAT ')'
        concat ' OUTPUT(*OUTFILE)'
        concat ' OUTFILE(' concat WrkFileOS concat ')'
        ;
    CALL QSYS2.QCMDEXC (Cmd);

    -- If DSPGMREF failed, build a record showing error
    -- occurred and return.
    if error_msg <> ' ' then
        -- <<<<<< Change this table library >>>>>>>
        insert into lennonsb.refs values (
            p_Depth,
            v_INLIB,
            v_INPGM,
            v_INTYPE,
            error_msg,
            '*ERROR',
            '*ERROR',
            '*ERROR'
        );
        set error_msg = ' ';
        return;
    end if;

        -- Open cursor over the outfile from DSPPGMREF 
    set WrkFileSQL = WrkLib 
        concat trim(WrkFileSQL) 
        concat trim(char(p_Depth));
    -- WrkLib and WrkFileSQL are controlled by this procedure, but
    -- the resulting name is concatenated into a PREPARE, so check
    -- defensively that it is still a plain qualified SQL name.
    if trim(translate(replace(WrkFileSQL, '.', ''),
        repeat(' ', length(name_chars)), name_chars)) <> '' then
        -- <<<<<< Change this table library >>>>>>>
        insert into lennonsb.refs values (
            p_Depth,
            p_INLIB,
            p_inpgm,
            p_INTYPE,
            'Invalid work file name',
            '*ERROR',
            '*ERROR',
            '*ERROR'
        );
        return;
    end if;
    set ref_cursor_txt = ref_cursor_txt concat WrkFileSQL;
    prepare ref_cursor_stmt from ref_cursor_txt;
    open    ref_cursor;
    -- Read through the records from DSPPGMREF
    Refs_Loop: loop
        fetch   from ref_cursor into  
         CALLER_LIBRARY
        ,CALLER_NAME   
        ,CALLER_TEXT   
        ,USES_LIBRARY  
        ,USES_NAME     
        ,USES_TYPE     
        ; 
        if sqlstate = no_more_data then 
            leave Refs_Loop;
        end if;
        -- <<<<<< Change this table library >>>>>>>
        insert into lennonsb.refs values (
             p_Depth
            ,CALLER_LIBRARY
            ,CALLER_NAME   
            ,p_INTYPE
            ,CALLER_TEXT   
            ,USES_LIBRARY  
            ,USES_NAME     
            ,USES_TYPE     
            );
            -- If used object already exists don't add again
            if my_sqlstate = duplicate_key then
                set my_sqlstate = ' ';
                iterate Refs_Loop;
            end if; 
            -- Don't expand IBM stuff further
            if substr(USES_LIBRARY, 1, 1) = 'Q' then
                iterate Refs_Loop;
            end if; 
            -- No further expansion if DSPPGMREF doesn't handle object 
            if USES_TYPE not in 
                ( '*PGM', '*SRVPGM', '*MODULE', '*QRYDFN', '*SQLPKG') then
                iterate Refs_Loop;
            end if; 
            -- Recursively expand this object
            -- Values come from the DSPPGMREF outfile and are
            -- validated again by the recursive call.
            call pgm_refs(
                USES_LIBRARY, USES_NAME, trim(USES_TYPE), p_Depth+1);
    end loop; 

    close   ref_cursor;
    set Cmd = 'DLTF FILE(' concat WrkFileOS concat ')';
    CALL QSYS2.QCMDEXC (Cmd);

    -- drop table WrkFileSQL;
end;