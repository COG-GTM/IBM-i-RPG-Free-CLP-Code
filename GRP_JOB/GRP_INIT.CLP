GR_INIT: +
  PGM

/*=== Initial program to run in a programmer group job =============*/
/* Called from GRP.                                                 */
/*    Command to run is in *GDA                                     */
/*    Library list is inherited from calling job                    */
/* Simply establishes the job, does setup, and transfers back       */
/*==================================================================*/
/* SECURITY / TRUST MODEL                                           */
/*   The command run below comes from the *GDA, which is shared by  */
/*   all the group jobs of one interactive session and is set by    */
/*   GRP in that same session. It is run as is with QCMDEXC, so it  */
/*   is a command of the developer's own choosing, running under    */
/*   the developer's own authority, in the developer's own job.     */
/*   Anyone able to change the *GDA of that job can therefore run   */
/*   any command that the job is authorized to.                     */
/*   This is a developer utility: do NOT reuse this pattern where   */
/*   the command text can come from untrusted input (a data base    */
/*   field, a screen field, a parameter from another user), and do  */
/*   not adopt authority in this program.                           */
/*==================================================================*/

  DCL VAR(&GDA)        TYPE(*CHAR) LEN(512)

/*== Get command to run ============================================*/
  RTVDTAARA DTAARA(*GDA) RTNVAR(&GDA)

/*=== Set my own attention program for this job ====================*/
  SETATNPGM PGM(GRP_ATN)

/*=== Fix print files to sensible defaults =========================*/
  OVRPRTF FILE(QPQXPRTF) PAGESIZE(*N 132)

/*=== And go right back to caller to continue initialization =======*/
  TFRGRPJOB GRPJOB(*PRV)

/*=== Resume here when selected from menu ==========================*/
/* -- Run the command specified in the *GDA                   */
/* -- Hitting the attention key suspends this job and invokes */
/*    the attention program.  This job may resume, or another */
/*    job may resume.                                         */
/* -- Exit from running program cleans up the environment,    */
/*    then loops back to start the program again.             */

/* Never pass a blank command to QCMDEXC: end the group job   */
/* instead of looping on an error.                            */

LOOP: +
  IF COND(&GDA *EQ ' ') THEN(GOTO CMDLBL(ENDPGM))
  CALL PGM(QCMDEXC) PARM(&GDA 512)
  RCLRSC
  RCLACTGRP ACTGRP(*ELIGIBLE) /* Not a good practice in production*/
  GOTO CMDLBL(LOOP)

ENDPGM: +
  ENDPGM
