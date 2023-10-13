#include "config.h"
#include <epan/packet.h>

#define CSP_PORT 1234

static int proto_csp = -1;

void
proto_register_csp(void)
{
    proto_csp = proto_register_protocol (
        "Cubesat Space Protocol", /* name        */
        "CSP",          /* short name  */
        "csp"           /* filter_name */
        );
}

void
proto_reg_handoff_csp(void)
{
    static dissector_handle_t csp_handle;

    csp_handle = create_dissector_handle(dissect_csp, proto_csp);
    dissector_add_uint("udp.port", CSP_PORT, csp_handle);
}

static int
dissect_csp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CSP");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_csp, tvb, 0, -1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

// CSP should be big-endian
//https://bytebucket.org/bbruner0/albertasat-on-board-computer/wiki/1.%20Resources/1.1.%20DataSheets/CSP/GS-CSP-1.1.pdf?rev=316ebd49bed49fdbb1d74efdeab74430e7cc726a

