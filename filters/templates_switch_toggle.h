/* Frame (60 bytes) */

#define pkt_switch_init_sz 60

static const unsigned char pkt_switch_init[pkt_switch_init_sz] = {
0x00, 0xe0, 0xa8, 0xb0, 0x58, 0xc4, 0x00, 0xa0, /* ....X... */
0x45, 0xb1, 0xb4, 0x80, 0x08, 0x00, 0x45, 0x00, /* E.....E. */
0x00, 0x2e, 0x0e, 0xad, 0x40, 0x00, 0x7f, 0x06, /* ....@... */
0xd1, 0xd3, 0x0a, 0x7f, 0x06, 0xe3, 0x0a, 0x82, /* ........ */
0xff, 0x65, 0xfe, 0x04, 0x09, 0x64, 0x69, 0x55, /* .e...diU */
0x6f, 0x8c, 0x70, 0xc4, 0x9c, 0x06, 0x50, 0x18, /* o.p...P. */
0x01, 0x02, 0xf1, 0x60, 0x00, 0x00, 0x68, 0x04, /* ...`..h. */
0x01, 0x00, 0x4c, 0x00                          /* ..L. */
};

/* Frame (70 bytes) */
#define pkt_switch_act_select_sz 70
static const unsigned char pkt_switch_act_select[pkt_switch_act_select_sz] = {
0x00, 0xe0, 0xa8, 0xb0, 0x58, 0xc4, 0x00, 0xa0, /* ....X... */
0x45, 0xb1, 0xb4, 0x80, 0x08, 0x00, 0x45, 0x00, /* E.....E. */
0x00, 0x38, 0x10, 0xc0, 0x40, 0x00, 0x7f, 0x06, /* .8..@... */
0xcf, 0xb6, 0x0a, 0x7f, 0x06, 0xe3, 0x0a, 0x82, /* ........ */
0xff, 0x65, 0xfe, 0x04, 0x09, 0x64, 0x69, 0x55, /* .e...diU */
0x6f, 0x92, 0x70, 0xc4, 0x9c, 0x06, 0x50, 0x18, /* o.p...P. */
0x01, 0x02, 0x87, 0xba, 0x00, 0x00, 0x68, 0x0e, /* ......h. */
0x08, 0x00, 0x4c, 0x00, 0x2e, 0x01, 0x06, 0x00, /* ..L..... */
0x2c, 0x03, 0x01, 0x03, 0x01, 0x85              /* ,..... */
};

/* Frame (70 bytes) */

/*
static const unsigned char pkt_switch_act_select_con[70] = {
0x00, 0xa0, 0x45, 0xb1, 0xb4, 0x80, 0x00, 0xe0,
0xa8, 0xb0, 0x58, 0xc4, 0x08, 0x00, 0x45, 0x00,
0x00, 0x38, 0x2c, 0x86, 0x00, 0x00, 0x3c, 0x06,
0x36, 0xf1, 0x0a, 0x82, 0xff, 0x65, 0x0a, 0x7f,
0x06, 0xe3, 0x09, 0x64, 0xfe, 0x04, 0x70, 0xc4,
0x9c, 0x06, 0x69, 0x55, 0x6f, 0xa2, 0x50, 0x18,
0x20, 0x00, 0x65, 0x4c, 0x00, 0x00, 0x68, 0x0e,
0x4c, 0x00, 0x0a, 0x00, 0x2e, 0x01, 0x07, 0x60,
0x2c, 0x03, 0x01, 0x03, 0x01, 0x85
};
*/

/* Frame (70 bytes) */
#define pkt_switch_act_exec_sz 70
static const unsigned char pkt_switch_act_exec[pkt_switch_act_exec_sz] = {
0x00, 0xe0, 0xa8, 0xb0, 0x58, 0xc4, 0x00, 0xa0, /* ....X... */
0x45, 0xb1, 0xb4, 0x80, 0x08, 0x00, 0x45, 0x00, /* E.....E. */
0x00, 0x38, 0x10, 0xc3, 0x40, 0x00, 0x7f, 0x06, /* .8..@... */
0xcf, 0xb3, 0x0a, 0x7f, 0x06, 0xe3, 0x0a, 0x82, /* ........ */
0xff, 0x65, 0xfe, 0x04, 0x09, 0x64, 0x69, 0x55, /* .e...diU */
0x6f, 0xa2, 0x70, 0xc4, 0x9c, 0x16, 0x50, 0x18, /* o.p...P. */
0x01, 0x02, 0x84, 0x1a, 0x00, 0x00, 0x68, 0x0e, /* ......h. */
0x0a, 0x00, 0x4e, 0x00, 0x2e, 0x01, 0x06, 0x00, /* ..N..... */
0x2c, 0x03, 0x01, 0x03, 0x01, 0x05              /* ,..... */
};

/* Frame (70 bytes) */
/*
static const unsigned char pkt_switch_act_exec_con[70] = {
0x00, 0xa0, 0x45, 0xb1, 0xb4, 0x80, 0x00, 0xe0,
0xa8, 0xb0, 0x58, 0xc4, 0x08, 0x00, 0x45, 0x00,
0x00, 0x38, 0x2c, 0x87, 0x00, 0x00, 0x3c, 0x06,
0x36, 0xf0, 0x0a, 0x82, 0xff, 0x65, 0x0a, 0x7f,
0x06, 0xe3, 0x09, 0x64, 0xfe, 0x04, 0x70, 0xc4,
0x9c, 0x16, 0x69, 0x55, 0x6f, 0xb2, 0x50, 0x18,
0x20, 0x00, 0x61, 0xac, 0x00, 0x00, 0x68, 0x0e,
0x4e, 0x00, 0x0c, 0x00, 0x2e, 0x01, 0x07, 0x60,
0x2c, 0x03, 0x01, 0x03, 0x01, 0x05
};
*/

/* Frame (81 bytes) */
static const unsigned char pkt27[81] = {
0x00, 0xa0, 0x45, 0xb1, 0xb4, 0x80, 0x00, 0xe0, /* ..E..... */
0xa8, 0xb0, 0x58, 0xc4, 0x08, 0x00, 0x45, 0x00, /* ..X...E. */
0x00, 0x43, 0x2c, 0x88, 0x00, 0x00, 0x3c, 0x06, /* .C,...<. */
0x36, 0xe4, 0x0a, 0x82, 0xff, 0x65, 0x0a, 0x7f, /* 6....e.. */
0x06, 0xe3, 0x09, 0x64, 0xfe, 0x04, 0x70, 0xc4, /* ...d..p. */
0x9c, 0x26, 0x69, 0x55, 0x6f, 0xb2, 0x50, 0x18, /* .&iUo.P. */
0x20, 0x00, 0x31, 0x61, 0x00, 0x00, 0x68, 0x19, /*  .1a..h. */
0x50, 0x00, 0x0c, 0x00, 0x24, 0x01, 0x03, 0x00, /* P...$... */
0x2c, 0x03, 0x04, 0x04, 0x03, 0xc4, 0x52, 0x7c, /* ,.....R| */
0x41, 0x00, 0xce, 0x3b, 0x3b, 0x0a, 0x88, 0x02, /* A..;;... */
0x12                                            /* . */
};

/* Frame (77 bytes) */
static const unsigned char pkt29[77] = {
0x00, 0xa0, 0x45, 0xb1, 0xb4, 0x80, 0x00, 0xe0, /* ..E..... */
0xa8, 0xb0, 0x58, 0xc4, 0x08, 0x00, 0x45, 0x00, /* ..X...E. */
0x00, 0x3f, 0x2c, 0x89, 0x00, 0x00, 0x3c, 0x06, /* .?,...<. */
0x36, 0xe7, 0x0a, 0x82, 0xff, 0x65, 0x0a, 0x7f, /* 6....e.. */
0x06, 0xe3, 0x09, 0x64, 0xfe, 0x04, 0x70, 0xc4, /* ...d..p. */
0x9c, 0x41, 0x69, 0x55, 0x6f, 0xb2, 0x50, 0x18, /* .AiUo.P. */
0x20, 0x00, 0xb7, 0x90, 0x00, 0x00, 0x68, 0x15, /*  .....h. */
0x52, 0x00, 0x0c, 0x00, 0x1f, 0x01, 0x0b, 0x00, /* R....... */
0x2c, 0x03, 0x01, 0x01, 0x01, 0x01, 0xdc, 0x3b, /* ,......; */
0x3b, 0x0a, 0x88, 0x02, 0x12                    /* ;.... */
};

/* Frame (70 bytes) */
static const unsigned char pkt31[70] = {
0x00, 0xa0, 0x45, 0xb1, 0xb4, 0x80, 0x00, 0xe0, /* ..E..... */
0xa8, 0xb0, 0x58, 0xc4, 0x08, 0x00, 0x45, 0x00, /* ..X...E. */
0x00, 0x38, 0x2c, 0x8a, 0x00, 0x00, 0x3c, 0x06, /* .8,...<. */
0x36, 0xed, 0x0a, 0x82, 0xff, 0x65, 0x0a, 0x7f, /* 6....e.. */
0x06, 0xe3, 0x09, 0x64, 0xfe, 0x04, 0x70, 0xc4, /* ...d..p. */
0x9c, 0x58, 0x69, 0x55, 0x6f, 0xb2, 0x50, 0x18, /* .XiUo.P. */
0x20, 0x00, 0x58, 0x6a, 0x00, 0x00, 0x68, 0x0e, /*  .Xj..h. */
0x54, 0x00, 0x0c, 0x00, 0x2e, 0x01, 0x0a, 0x60, /* T......` */
0x2c, 0x03, 0x01, 0x03, 0x01, 0x05              /* ,..... */
};

/* Frame (60 bytes) */
static const unsigned char pkt50[60] = {
0x00, 0xe0, 0xa8, 0xb0, 0x58, 0xc4, 0x00, 0xa0, /* ....X... */
0x45, 0xb1, 0xb4, 0x80, 0x08, 0x00, 0x45, 0x00, /* E.....E. */
0x00, 0x2e, 0x13, 0x31, 0x40, 0x00, 0x7f, 0x06, /* ...1@... */
0xcd, 0x4f, 0x0a, 0x7f, 0x06, 0xe3, 0x0a, 0x82, /* .O...... */
0xff, 0x65, 0xfe, 0x04, 0x09, 0x64, 0x69, 0x55, /* .e...diU */
0x6f, 0xb2, 0x70, 0xc4, 0x9c, 0x68, 0x50, 0x18, /* o.p..hP. */
0x01, 0x02, 0xe6, 0xd8, 0x00, 0x00, 0x68, 0x04, /* ......h. */
0x01, 0x00, 0x56, 0x00                          /* ..V. */
};

