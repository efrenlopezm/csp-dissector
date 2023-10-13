#include "config.h"
#include <epan/packet.h>

#define CSP_PORT 1234

static int proto_csp = -1;
static int hf_csp_pdu_type = -1;
static int ett_csp = -1;
static int hf_csp_flags = -1;
static int hf_csp_sequenceno = -1;
static int hf_csp_initialip = -1;

void
proto_register_csp(void)
{
    static hf_register_info hf[] = {
        { &hf_csp_pdu_type,
            { "CSP PDU Type", "csp.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_csp
    };

    proto_csp = proto_register_protocol (
        "Cubesat Space Protocol", /* name        */
        "CSP",          /* short name  */
        "csp"           /* filter_name */
        );
    
    proto_register_field_array(proto_csp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
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
    int offset = 0;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CSP");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_csp, tvb, 0, -1, ENC_BIG_ENDIAN);
    proto_tree *csp_tree = proto_item_add_subtree(ti, ett_csp);
    proto_tree_add_item(csp_tree, hf_csp_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

// CSP should be big-endian
//https://bytebucket.org/bbruner0/albertasat-on-board-computer/wiki/1.%20Resources/1.1.%20DataSheets/CSP/GS-CSP-1.1.pdf?rev=316ebd49bed49fdbb1d74efdeab74430e7cc726a

