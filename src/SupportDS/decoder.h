#ifndef DECODER_H
#define DECODER_H

#include"../utils/coding.h"
#include <math.h>
#include"sc-vector.h"

sc_array_def(struct pdu_ipv4,pdu_ipv4);

void parse_hpdu_v4(struct hpdu_ipv4 *pdu, struct sc_array_pdu_ipv4 *arr);

sc_array_def(struct pdu_ipv6,pdu_ipv6);

void parse_hpdu_v6(struct hpdu_ipv6 *pdu, struct sc_array_pdu_ipv6 *arr);

#endif