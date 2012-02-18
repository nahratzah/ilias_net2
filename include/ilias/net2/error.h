#ifndef ILIAS_NET2_ERROR_H
#define ILIAS_NET2_ERROR_H


/* Ilias net2 specific error classes. */
#define NET2_ERRCLASS_MASK		 0xff000000 /* Classification matk. */
#define NET2_ERRCLASS_CONNECT		 0x01000000 /* Connect errors. */

/*
 * Ilias net2 specific error conditions.
 */

/* Connect failed, due to missing signing algorithms. */
#define NET2_ERR_CONN_REQ_SIGN		(0x00000001 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to missing encryption algorithms. */
#define NET2_ERR_CONN_REQ_ENC		(0x00000002 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to missing remote host signature. */
#define NET2_ERR_CONN_REQ_SIGNATURE	(0x00000003 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to signature mismatch (possibly foiled mitm attack). */
#define NET2_ERR_CONN_MITM		(0x00000004 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to response timeout. */
#define NET2_ERR_CONN_TIMEOUT		(0x00000005 | NET2_ERRCLASS_CONNECT)


#endif /* ILIAS_NET2_ERROR_H */
