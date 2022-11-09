/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "auth.h"

bool_t
xdr_oauth_status (XDR *xdrs, oauth_status *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_action (XDR *xdrs, action *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_oauth_response (XDR *xdrs, oauth_response *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->token, ~0))
		 return FALSE;
	 if (!xdr_oauth_status (xdrs, &objp->status))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_s_req_token (XDR *xdrs, s_req_token *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->id, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->token, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_s_val_act (XDR *xdrs, s_val_act *objp)
{
	register int32_t *buf;

	 if (!xdr_action (xdrs, &objp->act))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->resource, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->token, ~0))
		 return FALSE;
	return TRUE;
}
