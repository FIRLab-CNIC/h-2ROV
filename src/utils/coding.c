#include"coding.h"

char* msubstring(char *destination, const char *source, int beg, int n)
{
    while (n > 0)
    {
        *destination = *(source + beg);
        destination++;
        source++;
        n--;
    }
 
    *destination = '\0';
    return destination;
}

void pdu_v4(struct pdu_ipv4 * p, int ip_version, ipv4 prefix, uint8_t len, uint8_t maxlen, uint32_t asn){
    p->ver = 1;
    p->type = ip_version;
    p->reserved = 0;
    p->len = 20;
    p->flags = 1;
    p->prefix_len = len;
    p->max_prefix_len = maxlen;
    p->zero = 0;
    p->prefix = prefix;
    p->asn = asn;
}

void pdu_v6(struct pdu_ipv6 * p, int ip_version, struct ip6_t prefix, uint8_t len, uint8_t maxlen, uint32_t asn){
    p->ver = 1;
    p->type = ip_version;
    p->reserved = 0;
    p->len = 32;
    p->flags = 1;
    p->prefix_len = len;
    p->max_prefix_len = maxlen;
    p->zero = 0;
    for(int i=0;i<4;i++)
    {
        p->prefix[i] = prefix.u_ip6.u_ip6_addr32[i];
    }
    p->asn = asn;
}

void init_pdu_v4(struct pdu_ipv4 * p, int ip_version, char * prefix, uint8_t len, uint8_t maxlen, uint32_t asn)
{
    struct lrtr_ip_addr addr;
    p->ver = 1;
    p->type = ip_version;
    p->reserved = 0;
    p->len = 20;
    p->flags = 1;
    p->prefix_len = len;
    p->max_prefix_len = maxlen;
    p->zero = 0;
    lrtr_ip_str_to_addr(prefix, &addr);
    p->prefix = addr.u.addr4.addr;
    p->asn = asn;
}

void init_pdu_v6(struct pdu_ipv6 * p, int ip_version, char * prefix, uint8_t len, uint8_t maxlen, uint32_t asn)
{
    struct lrtr_ip_addr addr;
    p->ver = 1;
    p->type = ip_version;
    p->reserved = 0;
    p->len = 32;
    p->flags = 1;
    p->prefix_len = len;
    p->max_prefix_len = maxlen;
    p->zero = 0;
    lrtr_ip_str_to_addr(prefix, &addr);
    for(int i=0;i<4;i++)
    {
        p->prefix[i] = addr.u.addr6.addr[i];
    }
    p->asn = asn;
}

void init_hpdu_v4_rd(struct hpdu_ipv4 * p, char * prefix, int hanging_level, uint32_t bitmap, uint32_t asn){
    char * p_end;
    p->ver = 1;
    p->type = HROV_IPV4;
    p->reserved = 0;
    p->len = 20;
    uint32_t pfx = strtol(prefix,&p_end, 16);
    p->sub_tree_identifier = (pfx >> (32-hanging_level))|(1<<hanging_level);
    p->Encoded_sub_tree = bitmap;
    p->asn = asn;
}

void init_hpdu_v6_rd(struct hpdu_ipv6 * p, char * prefix, int hanging_level, uint32_t bitmap, uint32_t asn){
    p->ver = 1;
    p->type = HROV_IPV6;
    p->reserved = 0;
    p->len = 32;
    struct lrtr_ip_addr pfx;
    for(int i=0;i<4;i++)
    {
        char dest[8];
        msubstring(dest,prefix,i*8,8);
        char * p_end;
        pfx.u.addr6.addr[i] = strtol(dest,&p_end,16);
    }	
    uint32_t identifer[4];
    get_subtree_identifier_v6(identifer,pfx.u.addr6.addr,hanging_level);
    memcpy(p->sub_tree_identifier,identifer,sizeof(uint32_t)*4);
    p->Encoded_sub_tree = bitmap;
    p->asn = asn;
}

void init_pdu_v4_rd(struct pdu_ipv4 * p, int ip_version, char * prefix, uint8_t len, uint8_t maxlen, uint32_t asn){
    char * p_end;
    p->ver = 1;
    p->type = ip_version;
    p->reserved = 0;
    p->len = 32;
    p->flags = 1;
    p->prefix_len = len;
    p->max_prefix_len = maxlen;
    p->zero = 0;
    p->prefix = strtol(prefix,&p_end, 16);
    p->asn = asn;
}

void init_pdu_v6_rd(struct pdu_ipv6 * p, int ip_version, char * prefix, uint8_t len, uint8_t maxlen, uint32_t asn)
{
    p->ver = 1;
    p->type = ip_version;
    p->reserved = 0;
    p->len = 32;
    p->flags = 1;
    p->prefix_len = len;
    p->max_prefix_len = maxlen;
    p->zero = 0;
    int i=0;
    while(i<4)
    {
        char dest[8];
        int j=i;
        msubstring(dest,prefix,j*8,8);
        char * p_end;
        p->prefix[i] = strtol(dest,&p_end,16);
        i++;
    }	
    p->asn = asn;
}

void init_hpdu_v4(struct hpdu_ipv4 * p, char * identifier, uint32_t bitmap, uint32_t asn)
{
    char * p_end;
    p->ver = 1;
    p->type = HROV_IPV4;
    p->reserved = 0;
    p->len = 20;
    p->sub_tree_identifier = strtol(identifier, &p_end, 16);
    p->Encoded_sub_tree = bitmap;
    p->asn = asn;
}



void init_hpdu_v6(struct hpdu_ipv6 * p, char * identifier, uint32_t bitmap, uint32_t asn)
{
    p->ver = 1;
    p->type = HROV_IPV6;
    p->reserved = 0;
    p->len = 32;
    for(int i=0;i<4;i++)
    {
        char dest[8];
        msubstring(dest,identifier,i*8,8);
        char * p_end;
        p->sub_tree_identifier[i] = strtol(dest,&p_end,16);
    }	
    p->Encoded_sub_tree = bitmap;
    p->asn = asn;
}

void * hrov_style_coding(char * raw_data, int *counter)
{
    char * token = strtok(raw_data, " ");
    char * data[4];
    int i=0;
    while( token != NULL ) {
        data[i] = token;
        token = strtok(NULL, " ");
        i++;
    }
    char *tmp = NULL;
    if ((tmp = strstr(data[3], "\n")))
    {
        *tmp = '\0';
    }
    uint32_t originASN = atoi(data[3]);
    char * p_end;
    uint32_t bitmap = strtol(data[2], &p_end, 16);
    *counter =  __builtin_popcount(bitmap);
    char * identifier = data[1];
    if(strlen(data[1])==8){
        struct hpdu_ipv4 * pdu = (struct hpdu_ipv4 *)malloc(sizeof(struct hpdu_ipv4));
        init_hpdu_v4(pdu, identifier, bitmap, originASN);
        return pdu;
    }else{
        struct hpdu_ipv6 * pdu = (struct hpdu_ipv6 *)malloc(sizeof(struct hpdu_ipv6));
        init_hpdu_v6(pdu, identifier, bitmap, originASN);
        return pdu;
    }
}

void * hrov_style_coding_it(char * raw_data)
{
    char * token = strtok(raw_data, " ");
    char * data[4];
    int i=0;
    while( token != NULL ) {
        data[i] = token;
        token = strtok(NULL, " ");
        i++;
    }
    char *tmp = NULL;
    if ((tmp = strstr(data[3], "\n")))
    {
        *tmp = '\0';
    }
    uint32_t originASN = atoi(data[3]);
    char * p_end;
    uint32_t bitmap = strtol(data[2], &p_end, 16);
    char * prefix_len = data[1];
    char * ntoken = strtok(prefix_len,"/");
    char * ndata[2];
    i=0;
    while( ntoken != NULL ) {
        ndata[i] = ntoken;
        ntoken = strtok(NULL, " ");
        i++;
    }
    char * prefix = ndata[0];
    int hanging_level = atoi(ndata[1]);
    struct lrtr_ip_addr pfx;
    lrtr_ip_str_to_addr(prefix, &pfx);
    if(!strchr(prefix,':')){
        uint32_t identifier;
        identifier = (pfx.u.addr4.addr >> (32-hanging_level))|(1<<hanging_level);
        struct hpdu_ipv4 * p = (struct hpdu_ipv4 *)malloc(sizeof(struct hpdu_ipv4));
        p->ver = 1;
        p->type = HROV_IPV4;
        p->reserved = 0;
        p->len = 20;
        p->sub_tree_identifier = identifier;
        p->Encoded_sub_tree = bitmap;
        p->asn = originASN;
        return p;
    }else{
        uint32_t identifer[4];
        get_subtree_identifier_v6(identifer,pfx.u.addr6.addr,hanging_level);
        struct hpdu_ipv6 * p = (struct hpdu_ipv6 *)malloc(sizeof(struct hpdu_ipv6));
        p->ver = 1;
        p->type = HROV_IPV6;
        p->reserved = 0;
        p->len = 32;
        for(int i=0;i<4;i++)
        {
            p->sub_tree_identifier[i] = identifer[i];
        }	
        p->Encoded_sub_tree = bitmap;
        p->asn = originASN;
        return p;
    }
}

void * trov_style_coding_it(char * raw_data)
{
    char * token = strtok(raw_data, " ");
    char * data[4];
    int i=0;
    while( token != NULL ) {
        data[i] = token;
        token = strtok(NULL, " ");
        i++;
    }
    int maxlen=atoi(data[2]);
    uint32_t originASN=atoi(data[3]);
    char * prefix_len = data[1];
    char * ndata[2];
    char * ntoken = strtok(prefix_len,"/");
    i=0;
    while(ntoken!=NULL){
        ndata[i] = ntoken;
        ntoken = strtok(NULL, "/");
        i++;
    }
    char * prefix = ndata[0];
    int len=atoi(ndata[1]);
    if(strchr(prefix,':'))
    {
        struct pdu_ipv6 * pdu = (struct pdu_ipv6*)malloc(sizeof(struct pdu_ipv6));
        init_pdu_v6(pdu, TROA_IPV6, prefix, len, maxlen, originASN);
        return (void *)pdu;
    }
    else
    {
        struct pdu_ipv4 * pdu = (struct pdu_ipv4*)malloc(sizeof(struct pdu_ipv4));
        init_pdu_v4(pdu, TROA_IPV4, prefix, len, maxlen, originASN);
        return (void *)pdu;
    }
}

void * trov_style_coding(char * raw_data)
{
    char * token = strtok(raw_data, " ");
    char * data[5];
    int i=0;
    while( token != NULL ) {
        data[i] = token;
        token = strtok(NULL, " ");
        i++;
    }
    int len=atoi(data[2]);
    int maxlen=atoi(data[3]);
    uint32_t originASN=atoi(data[4]);
    char * prefix = data[1];
    if(strchr(prefix,':'))
    {
        struct pdu_ipv6 * pdu = (struct pdu_ipv6*)malloc(sizeof(struct pdu_ipv6));
        init_pdu_v6(pdu, TROA_IPV6, prefix, len, maxlen, originASN);
        return (void *)pdu;
    }
    else
    {
        struct pdu_ipv4 * pdu = (struct pdu_ipv4*)malloc(sizeof(struct pdu_ipv4));
        init_pdu_v4(pdu, TROA_IPV4, prefix, len, maxlen, originASN);
        return (void *)pdu;
    }
}

void * mrov_style_coding_it(char * raw_data)
{
    char * token = strtok(raw_data, " ");
    char * data[4];
    int i=0;
    while( token != NULL ) {
        data[i] = token;
        token = strtok(NULL, " ");
        i++;
    }
    int len=atoi(data[2]);
    uint32_t originASN=atoi(data[3]);
    char * prefix_len = data[1];
    char * prefix = strtok(prefix_len, "/");
    if(strchr(prefix,':'))
    {
        struct pdu_ipv6 * pdu = (struct pdu_ipv6*)malloc(sizeof(struct pdu_ipv6));
        init_pdu_v6(pdu, TROA_IPV6, prefix, len, len, originASN);
        return (void *)pdu;
    }
    else
    {
        struct pdu_ipv4 * pdu = (struct pdu_ipv4*)malloc(sizeof(struct pdu_ipv4));
        init_pdu_v4(pdu, TROA_IPV4, prefix, len, len, originASN);
        return (void *)pdu;
    }
}


void * mrov_style_coding(char * raw_data)
{
    char * token = strtok(raw_data, " ");
    char * data[4];
    int i=0;
    while( token != NULL ) {
        data[i] = token;
        token = strtok(NULL, " ");
        i++;
    }
    int len=atoi(data[2]);
    uint32_t originASN=atoi(data[3]);
    char * prefix = data[1];
    if(strchr(prefix,':'))
    {
        struct pdu_ipv6 * pdu = (struct pdu_ipv6*)malloc(sizeof(struct pdu_ipv6));
        init_pdu_v6(pdu, TROA_IPV6, prefix, len, len, originASN);
        return (void *)pdu;
    }
    else
    {
        struct pdu_ipv4 * pdu = (struct pdu_ipv4*)malloc(sizeof(struct pdu_ipv4));
        init_pdu_v4(pdu, TROA_IPV4, prefix, len, len, originASN);
        return (void *)pdu;
    }
}

void bgp_coding(char * raw_data, void * record)
{
    char * token = strtok(raw_data, "|");
    char * res;
    int i=0;
    char * data[4];
    while( token != NULL ) {
        data[i] = token;    
        token = strtok(NULL, "|");
        i++;
    }
    char *tmp = NULL;
    if ((tmp = strstr(data[3], "\n")))
    {
        *tmp = '\0';
    }
    char * prefix = data[0];
    uint8_t masklen = atoi(data[1]);
    uint32_t asn = atoi(data[2]);
    res = data[3];
    struct updates_message * pfx = (struct updates_message *)record;
    lrtr_ip_str_to_addr(prefix, &pfx->addr);
    pfx->asn = asn;
    pfx->masklen = masklen;
    if(!strcmp(res,"valid"))
    {
        pfx->res = BGP_PFXV_STATE_VALID;
    }
    else if(!strcmp(res,"invalid"))
    {
        pfx->res = BGP_PFXV_STATE_INVALID;
    }
    else
    {
        pfx->res = BGP_PFXV_STATE_NOT_FOUND;
    }
}

void bgp_update_coding(char * raw_data, void * record)
{
    char * token = strtok(raw_data, " ");
    int i=0;
    char * data[4];
    while( token != NULL ) {
        data[i] = token;    
        token = strtok(NULL, " ");
        i++;
    }
    char *tmp = NULL;
    if ((tmp = strstr(data[3], "\n")))
    {
        *tmp = '\0';
    }
    char * prefix = data[1];
    uint8_t masklen = atoi(data[2]);
    uint32_t asn = atoi(data[3]);
    struct updates_message * pfx = (struct updates_message *)record;
    lrtr_ip_str_to_addr(prefix, &pfx->addr);
    pfx->asn = asn;
    pfx->masklen = masklen;
    pfx->res = BGP_PFXV_STATE_NOT_FOUND;
}

void print_bgp_update_record(struct updates_message record){
    char prefix_str[46];
    lrtr_ip_addr_to_str(&record.addr,prefix_str,46);
    printf("1 %s %d %u\n",prefix_str,record.masklen,record.asn);
}


void bgp_tmp_coding(char * raw_data, void * record)
{
    char * token = strtok(raw_data, " ");
    int i=0;
    char * data[3];
    while( token != NULL ) {
        data[i] = token;    
        token = strtok(NULL, " ");
        i++;
    }
    char *tmp = NULL;
    if ((tmp = strstr(data[2], "\n")))
    {
        *tmp = '\0';
    }

    char * prefix_len = data[1];
    char * ndata[2];
    char * ntoken = strtok(prefix_len,"/");
    i=0;
    while(ntoken!=NULL){
        ndata[i] = ntoken;
        ntoken = strtok(NULL, "/");
        i++;
    }
    char * prefix = ndata[0];
    int len=atoi(ndata[1]);

    uint32_t asn = atoi(data[2]);
    struct updates_message * pfx = (struct updates_message *)record;
    lrtr_ip_str_to_addr(prefix, &pfx->addr);
    pfx->asn = asn;
    pfx->masklen = len;
    pfx->res = BGP_PFXV_STATE_VALID;
    // if(pfx->addr.ver==LRTR_IPV4){
    //     printf("%u/%d %u\n",pfx->addr.u.addr4.addr,len,asn);
    // }
    // printf("%s/%d %u\n",prefix,len,asn);
}

void * mrov_coding_rd(char * raw_data){
    char * token = strtok(raw_data, " ");
    int i=0;
    char * data[5];
    while( token != NULL ) {
        data[i] = token;    
        token = strtok(NULL, " ");
        i++;
    }
    uint32_t asn = atoi(data[1]);
    int masklen = atoi(data[3]);
    int maxlen = atoi(data[4]);
    if(strlen(data[2])>8)
    {
        struct pdu_ipv6 * pdu = (struct pdu_ipv6*)malloc(sizeof(struct pdu_ipv6));
        init_pdu_v6_rd(pdu, TROA_IPV6, data[2], masklen, maxlen, asn);
        return (void *)pdu;
    }
    else
    {
        struct pdu_ipv4 * pdu = (struct pdu_ipv4*)malloc(sizeof(struct pdu_ipv4));
        init_pdu_v4_rd(pdu, TROA_IPV4, data[2], masklen, maxlen, asn);
        return (void *)pdu;
    }
}

void * hrov_coding_rd(char * raw_data){
    char * token = strtok(raw_data, " ");
    int i=0;
    char * data[5];
    while( token != NULL ) {
        data[i] = token;    
        token = strtok(NULL, " ");
        i++;
    }
    uint32_t asn = atoi(data[1]);
    char *pfx = data[2];
    int masklen = atoi(data[3]);
    if(asn==0){
        int maxlen = atoi(data[4]);
        if(strlen(pfx)<=8){
            struct pdu_ipv4 * pdu = (struct pdu_ipv4 *)malloc(sizeof(struct pdu_ipv4));
            init_pdu_v4_rd(pdu, TROA_IPV4, data[2], masklen, maxlen, asn);
            
            return (void *)pdu;
        }else{
            struct pdu_ipv6 * pdu = (struct pdu_ipv6 *)malloc(sizeof(struct pdu_ipv6));
            init_pdu_v6_rd(pdu, TROA_IPV6, data[2], masklen, maxlen, asn);
            
            return (void *)pdu;
        }
    }
    else{
        uint32_t bitmap = atoi(data[4]);
        if(strlen(pfx)<=8){
            struct hpdu_ipv4 * pdu = (struct hpdu_ipv4 *)malloc(sizeof(struct hpdu_ipv4));
            init_hpdu_v4_rd(pdu,data[2],masklen,bitmap,asn);
            // printf("%u %u %u\n",pdu->sub_tree_identifier,pdu->Encoded_sub_tree,pdu->asn);
            return (void *)pdu;
        }else{
            struct hpdu_ipv6 * pdu = (struct hpdu_ipv6 *)malloc(sizeof(struct hpdu_ipv6));
            init_hpdu_v6_rd(pdu,data[2],masklen,bitmap,asn);
            // printf("%u %u %u %u %u %u\n",pdu->sub_tree_identifier[0],pdu->sub_tree_identifier[1],pdu->sub_tree_identifier[2],pdu->sub_tree_identifier[3],pdu->Encoded_sub_tree,pdu->asn);
            return (void *)pdu;
        }
    }
}
