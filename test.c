#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<assert.h>
#include<stdlib.h>
#include <stdbool.h>
#include<sys/types.h>
#include<unistd.h>
#define __USE_GNU
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include<time.h>
#include"src/hrov_header.h"
#include"getopt.h"

#define LOG_SUCCESS(func)(printf("%s() successful\n", func))
#define LOG_ERROR(func)(printf("%s() error\n", func))
#define STANDORD_OUTPUT 0
#define BASH_CAL 1

static int mod=STANDORD_OUTPUT;
// int mod=BASH_CAL;

int select_algo(char *,char *,int,char *,char *,char *,char *,struct rov_algo_t *);
int rov_init(struct rov_algo_t *algo);
int basic_building(struct rov_algo_t *algo);
int withdrawn(struct rov_algo_t *algo);
int insert(struct rov_algo_t *algo);
int validate(struct rov_algo_t *algo);
int release(struct rov_algo_t *algo);
int mem_check(struct rov_algo_t *algo);
void test_diy();
void test_bird();
void unit_test();
void bind_to_cpu(int cpu_id);

void main(int argc,char *argv[])
{
    // test_mtoh();
    // test_htom();
    // test_diy();
    // test_bird();
    // unit_test();
    bind_to_cpu(7);
    struct rov_algo_t *algo;
    algo = (struct rov_algo_t *)malloc(sizeof(struct rov_algo_t));
    algo->ht = NULL;
    
    int opt;

    int upd_flag=0;
    int wide_threshold = 0;
    char *algo_name, *algo_mod, *insert_file, *upd_file,*validate_file, *result_file;
    while ((opt = getopt(argc, argv, "a:m:i:u:v:r:w:")) != -1) {
        switch (opt) {
            case 'a': 
                algo_name = optarg;
                break;
            case 'm': 
                algo_mod = optarg;
                break;
            case 'i':
                insert_file = optarg;
                break;
            case 'w':
                wide_threshold = atoi(optarg);
                break;
            case 'u':
                upd_file = optarg;
                upd_flag = 1;
                break;
            case 'v':
                validate_file = optarg;
                break;
            case 'r':
                result_file = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a:m:i:v:r:]\n", argv[0]);
                fprintf(stderr, "a : algo\n");
                fprintf(stderr, "m : mod\n");
                fprintf(stderr, "i : insert file\n");
                fprintf(stderr, "v : validate file\n");
                fprintf(stderr, "r : result file\n");
                exit(EXIT_FAILURE);
        }
    }
    if(select_algo(algo_name,algo_mod,wide_threshold,insert_file,upd_file,validate_file,result_file,algo)!=SUCCESS){
        LOG_ERROR("select algo");
    }
    if(rov_init(algo)!=SUCCESS){
        LOG_ERROR("rov init");
    }

    if(basic_building(algo)!=SUCCESS){
        LOG_ERROR("basic building");
    }

    // h_pfxt_print_nlbs(algo);
    // h_pfxt_print_basic(algo);
    
    // h_pfxt_print_nlbs(algo);
    if(upd_flag){
        if(withdrawn(algo)!=SUCCESS){
            LOG_ERROR("withdrawn");
        }

        // h_pfxt_print_nlbs(algo);
        
        // if(insert(algo)!=SUCCESS){
        //     LOG_ERROR("insert");
        // }
    }

    if(validate(algo)!=SUCCESS){
        LOG_ERROR("validate");
    }

    if(mem_check(algo)!=SUCCESS){
        LOG_ERROR("mem_check");
    }

    if(release(algo)!=SUCCESS){
        LOG_ERROR("release");
    }
  
    return;
}

void bind_to_cpu(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);        // 清空CPU集合
    CPU_SET(cpu_id, &cpuset); // 将指定的CPU核加入集合

    pid_t pid = getpid(); // 获取当前进程ID

    // 设置当前进程的CPU亲和性
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("sched_setaffinity");
        exit(EXIT_FAILURE);
    }

    printf("Process bound to CPU %d\n", cpu_id);
}

int select_algo(char *algo_name,char *algo_mod,int threshold,char *insert_file,char *upd_file,char *validate_file,char *result_file,struct rov_algo_t *algo){
    if(strcmp(algo_name,"hbasic") == 0){
        COPY_ALGO(algo,hrov_basic);
        algo->algo_name = "hbasic";
    } else if(strcmp(algo_name,"hbinary") == 0){
        COPY_ALGO(algo,hrov_binary);
        algo->algo_name = "hbinary";
    } else if(strcmp(algo_name,"hnlb") == 0){
        COPY_ALGO(algo,hrov_nlbs_binary); 
        algo->algo_name = "hnlb";
    } else if(strcmp(algo_name,"trov") == 0){
        COPY_ALGO(algo,trov); 
        algo->algo_name = "trov";
    } else if(strcmp(algo_name,"mrov") == 0){
        COPY_ALGO(algo,mrov); 
        algo->algo_name = "mrov";
    } else if(strcmp(algo_name,"bgp-srx")==0){
        COPY_ALGO(algo,bgp_srx);
        algo->algo_name = "bgp-srx";
    } else if(strcmp(algo_name,"bird") == 0){
        COPY_ALGO(algo,bird);
        algo->algo_name = "bird";
    } else if(strcmp(algo_name,"bird_trie") == 0){
        COPY_ALGO(algo,bird_trie);
        algo->algo_name = "bird_trie";
    }
    else {
        puts("Select algorithm error.\n");
        return EXIT_FAILURE;
    }
    algo->wide_threshold = threshold;
    if(strcmp(algo_mod,"standard")==0){
        mod=STANDORD_OUTPUT;
    }
    else if(strcmp(algo_mod,"bash")==0){
        mod=BASH_CAL;
    }
    else{
        puts("Select mod error.\n");
        return EXIT_FAILURE;
    }
    algo->files.pdu_file = insert_file;
    algo->files.upd_wth_file = upd_file;
    algo->files.validate_file = validate_file;
    algo->result_file = result_file;
    puts(insert_file);
    puts(validate_file);
    return SUCCESS;
}

int rov_init(struct rov_algo_t *algo){
    algo->rov_init(algo);
    if(mod==STANDORD_OUTPUT){
        LOG_SUCCESS(__func__);
        puts("---------------------");
    }
    return SUCCESS;
}

int mem_check(struct rov_algo_t *algo){
    if(mod==STANDORD_OUTPUT){
        algo->mem_check(algo->ht);
        LOG_SUCCESS(__func__);
        puts("---------------------");
    }
    else if(mod==BASH_CAL){
        FILE *fptr;
        fptr = fopen("./result_data/memory.txt","a");
        double memory = algo->mem_check_mute(algo->ht)/1024.0;
        fprintf(fptr,"%s, %fMB\n", algo->algo_name, memory);
        fclose(fptr);
    }
    return SUCCESS;
}

int basic_building(struct rov_algo_t *algo){
    FILE * fptr;
    ssize_t read;
    char * line = NULL;
    size_t len = 0;
    fptr = fopen(algo->files.pdu_file,"r");
    if (fptr == NULL)
        return EXIT_FAILURE;
    int cnt = 0;
    sc_array_def(void *,ptr);
    struct sc_array_ptr arr;
    sc_array_init(&arr);
    while ((read = getline(&line, &len, fptr)) != -1) {
        // puts(line);
        void * pdu = mrov_coding_rd(line);
        sc_array_add(&arr,pdu);
    }
    double judge_times = 0;
    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    for(int i = 0; i<sc_array_size(&arr);i++){
        void * pdu = sc_array_at(&arr,i);
        if(algo->rov_pfx_add(algo->ht,pdu)==PFX_ERROR) return EXIT_FAILURE;
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    double f = ((double)tend.tv_sec*1e9 + tend.tv_nsec) - ((double)tstart.tv_sec*1e9 + tstart.tv_nsec);
    judge_times += f/1e9;
    free(line);
    fclose(fptr);
    if(mod==STANDORD_OUTPUT){
        LOG_SUCCESS(__func__);
        printf("insertion speed: %f\n",sc_array_size(&arr)/judge_times/1000000);
        puts("---------------------");
    }
    else if(mod==BASH_CAL){
        FILE * wptr;
        wptr = fopen("./result_data/insert.txt","a");
        double insert_speed = sc_array_size(&arr)/judge_times/1000000;
        fprintf(wptr,"%f\n",insert_speed);
        fclose(wptr);
    }
    return SUCCESS;
}

int withdrawn(struct rov_algo_t *algo){
    double withdrawn_time=0;
    FILE * fptr;
    ssize_t read;
    char * line = NULL;
    size_t len = 0;
    int withdrawn_times=0;
    fptr = fopen(algo->files.upd_wth_file,"r");
    if (fptr == NULL)
        return EXIT_FAILURE;
    sc_array_def(void *,ptr);
    struct sc_array_ptr arr;
    sc_array_init(&arr);
    while ((read = getline(&line, &len, fptr)) != -1) {
        // puts(line);
        void * pdu = mrov_coding_rd(line);
        sc_array_add(&arr,pdu);
    }
    double judge_times = 0;
    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    for(int i = 0;i<sc_array_size(&arr);i++){
        void * pdu = sc_array_at(&arr,i);
        if(algo->rov_pfx_rm(algo->ht,pdu)==PFX_ERROR) return EXIT_FAILURE;
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    double f = ((double)tend.tv_sec*1e9 + tend.tv_nsec) - ((double)tstart.tv_sec*1e9 + tstart.tv_nsec);
    judge_times += f/1e9;
    if(mod==BASH_CAL){
        FILE * wptr;
        wptr = fopen("./result_data/withdrawn.txt","a");
        double withdraw_speed = sc_array_size(&arr)/judge_times/1000000;;
        fprintf(wptr,"%f\n",withdraw_speed);
        fclose(wptr);
    }
    else if(mod == STANDORD_OUTPUT){
        LOG_SUCCESS(__func__);
        double withdraw_speed = sc_array_size(&arr)/judge_times/1000000;;
        printf("withdrawn time consuming: %f\n", withdraw_speed);
        puts("---------------------");
    }
    free(line);
    fclose(fptr);
    return SUCCESS;
}

int insert(struct rov_algo_t *algo){
    FILE * fptr;
    ssize_t read;
    char * line = NULL;
    size_t len = 0;
    FILE * wptr;
    wptr = fopen("./result_data/insert.txt","a");
    double insert_time=0;
    int insert_times=0;
    fptr = fopen(algo->files.upd_wth_file,"r");
    if (fptr == NULL)
        return EXIT_FAILURE;
    while ((read = getline(&line, &len, fptr)) != -1) {
        clock_t start,end;
        puts("1");
        void * pdu = algo->test_data_coding(line);
        start = clock();
        if(algo->rov_pfx_add(algo->ht,pdu)==PFX_ERROR) return EXIT_FAILURE;
        end = clock();
        insert_time+=(double)(end-start)/CLOCKS_PER_SEC;
        insert_times+=1;
    }

    if(mod==BASH_CAL){
        fprintf(wptr, "%f\n", insert_time);
    }
    if(mod==STANDORD_OUTPUT){
        LOG_SUCCESS(__func__);
        printf("insert time consuming: %f s\n", insert_time);
        printf("insert Records: %d\n\tinsert Records per second: %.2f\n", insert_times, insert_times/insert_time);
        puts("---------------------");
    }
    free(line);
    fclose(fptr);
    fclose(wptr);
    return SUCCESS;
}

void get_cpu_times(unsigned long long *idle_time, unsigned long long *total_time) {
    FILE *file = fopen("/proc/stat", "r");
    if (file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char line[256];
    if (fgets(line, sizeof(line), file) == NULL) {
        perror("fgets");
        exit(EXIT_FAILURE);
    }
    fclose(file);

    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
           &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);

    *idle_time = idle + iowait;
    *total_time = user + nice + system + idle + iowait + irq + softirq + steal;
}

double calculate_cpu_load(unsigned long long idle_time, unsigned long long total_time,
                          unsigned long long prev_idle_time, unsigned long long prev_total_time) {
    unsigned long long idle_diff = idle_time - prev_idle_time;
    unsigned long long total_diff = total_time - prev_total_time;
    return (1.0 - (double)idle_diff / total_diff) * 100.0;
}

void warm_up(struct rov_algo_t *algo){
    FILE * fptr;
    ssize_t read;
    char * line = NULL;
    size_t len = 0;
    
    fptr = fopen("./test_data/nsdi_exp_20240825/sizerange/v6/warmup.txt","r");
    if (fptr == NULL)
        return;
    sc_array_def(struct updates_message,um);
    struct sc_array_um arr;
    sc_array_init(&arr);
    while ((read = getline(&line, &len, fptr)) != -1) {
        struct updates_message record;
        bgp_update_coding(line, &record);
        sc_array_add(&arr,record);
    }
    for(int i=0;i<sc_array_size(&arr);i++){
        struct updates_message record = sc_array_at(&arr,i);
        algo->rov_pfx_validate(algo->ht, arr.elems[i].asn, &arr.elems[i].addr, arr.elems[i].masklen, &arr.elems[i].res);
    }
    free(line);
    fclose(fptr);
    return;
}

int validate(struct rov_algo_t *algo){
    FILE * fptr;
    ssize_t read;
    char * line = NULL;
    size_t len = 0;
    
    fptr = fopen(algo->files.validate_file,"r");
    if (fptr == NULL)
    {
        printf("!!!!!!!! validate\n");
        return EXIT_FAILURE;
    }
    FILE * wptr;
    wptr = fopen(algo->result_file,"w");
    FILE * rptr;
    char validation_result[50] = "./result_data/validate_";
    strcat(validation_result, algo->algo_name);
    rptr = fopen(validation_result,"a");
    double judge_times=0;
    double min_time=INT64_MAX;
    double max_time=0;
    int counter=0;
    // warm_up(algo);
    sc_array_def(struct updates_message,um);
    struct sc_array_um arr;
    sc_array_init(&arr);
    while ((read = getline(&line, &len, fptr)) != -1) {
        struct updates_message record;
        bgp_update_coding(line, &record);
        sc_array_add(&arr,record);
    }
    // __builtin_prefetch(algo->ht);
    //single validate time
    sc_array_def(float,sf);
    struct sc_array_sf arr_validate_time;
    sc_array_init(&arr_validate_time);
    for(int x=0;x<20;x++){
        double f = 0;
        for(int i=0;i<sc_array_size(&arr);i++){
            enum pfxv_state res; 
            struct updates_message record = sc_array_at(&arr,i);
            struct timespec tstart={0,0}, tend={0,0};
            clock_gettime(CLOCK_MONOTONIC, &tstart);
            // print_bgp_update_record(record);
            algo->rov_pfx_validate(algo->ht, arr.elems[i].asn, &arr.elems[i].addr, arr.elems[i].masklen, &arr.elems[i].res);
            clock_gettime(CLOCK_MONOTONIC, &tend);
            f += ((double)tend.tv_sec*1e9 + tend.tv_nsec) - ((double)tstart.tv_sec*1e9 + tstart.tv_nsec);
            counter++;
        }
        f = f/1e9;
        // sc_array_add(&arr_validate_time,(double)sc_array_size(&arr)/f/1000000);
        sc_array_add(&arr_validate_time, f / (double)sc_array_size(&arr) * 1e6);
    }
    //print single validate time
    FILE * svptr;
    char validation_single_result[50] = "./result_data/validate_single_time";
    strcat(validation_single_result, algo->algo_name);
    svptr = fopen(validation_single_result,"w");
    for(int i=0;i<sc_array_size(&arr_validate_time);i++){
        fprintf(svptr,"%f MVPS\n",1/arr_validate_time.elems[i]);
        judge_times+=arr_validate_time.elems[i];
    }
    judge_times = judge_times/sc_array_size(&arr_validate_time);

    for(int i=0;i<sc_array_size(&arr);i++){
        enum pfxv_state res = arr.elems[i].res; 
        uint8_t masklen = arr.elems[i].masklen;
        uint32_t asn = arr.elems[i].asn;
        char prefix_str[46];
        lrtr_ip_addr_to_str(&arr.elems[i].addr,prefix_str,46);
        if(res==BGP_PFXV_STATE_VALID){
            fprintf(wptr,"%s/%u|%u|VALID\n",prefix_str,masklen,asn);
        }
        else if(res==BGP_PFXV_STATE_INVALID){
            fprintf(wptr,"%s/%u|%u|INVALID\n",prefix_str,masklen,asn);
        }
        else if(res==BGP_PFXV_STATE_NOT_FOUND){
            fprintf(wptr,"%s/%u|%u|NOTFOUND\n",prefix_str,masklen,asn);
        }
        else{
            puts("error");
            return EXIT_FAILURE;
        }    
    }

    if(mod==BASH_CAL){
        fprintf(rptr, "%.3f\n", (double)counter/judge_times/10000000);
        // fprintf(rptr, "%.3f\n", judge_times);
        // fprintf(rptr,"%.2f\n", cpu_load);
        // fprintf(rptr,  "%f\n", judge_times);
    }
    if(mod==STANDORD_OUTPUT){
        LOG_SUCCESS(__func__);
        printf("validate time consuming: %f\n", judge_times);
        printf("validate records: %d\n",counter);
        printf("million validate per second: %.3f\n", judge_times);
        printf("min second: %lf\n", min_time/1e3);
        printf("max second: %lf\n", max_time/1e3);
        puts("---------------------");
    }
    fclose(wptr);
    fclose(svptr);
    free(line);
    fclose(fptr);
    fclose(rptr);
    return SUCCESS;
}

int release(struct rov_algo_t *algo){
    algo->mem_release(algo->ht);
    free(algo);
    if(mod==STANDORD_OUTPUT){
        LOG_SUCCESS(__func__);
        puts("---------------------");
    }
    return SUCCESS;
}

void test_bird(){
    struct rov_algo_t *algo;
    algo = (struct rov_algo_t *)malloc(sizeof(struct rov_algo_t));
    algo->ht = NULL;
    COPY_ALGO(algo,bird_trie);

    algo->test_data_coding = mrov_coding_rd;
    algo->files.pdu_file = "./test_data/bird_test/vrp.txt";
    algo->files.validate_file = "./test_data/bird_test/update.txt";
    algo->result_file = "./test_data/test_result/hbasic/v4/result.txt";

    if(rov_init(algo)!=SUCCESS){
        LOG_ERROR("rov init");
    }

    FILE * fptr;
    ssize_t read;
    char * line = NULL;
    size_t len = 0;
    fptr = fopen(algo->files.pdu_file,"r");

    while ((read = getline(&line, &len, fptr)) != -1) {
        // puts(line);
        void * pdu = mrov_coding_rd(line);
        algo->rov_pfx_add(algo->ht,pdu);
        // h_pfxt_print_binary(algo);
        // puts("============");
    }
    free(line);
    fclose(fptr);
    
    LOG_SUCCESS("basic_building");

    bird_trie_basic_print(algo->ht);
    // hrov_table_basic_print(algo->ht);
    // h_pfxt_print_nlbs(algo);
    // h_pfxt_print_basic(algo);
    // h_pfxt_print_binary(algo);

    // if(withdrawn(algo)!=SUCCESS){
    //     LOG_ERROR("withdrawn");
    // }

    // h_pfxt_print_nlbs(algo);
    // h_pfxt_print_binary(algo);
    // h_pfxt_print_basic(algo);
    
    // if(insert(algo)!=SUCCESS){
    //     LOG_ERROR("insert");
    // }

    // h_pfxt_print_basic(algo);

    if(validate(algo)!=SUCCESS){
        LOG_ERROR("validate");
    }

    // if(mem_check(algo)!=SUCCESS){
    //     LOG_ERROR("mem_check");
    // }

    // if(release(algo)!=SUCCESS){
    //     LOG_ERROR("release");
    // }
}

void unit_test(){
    ipv4asn_uint32_map masn;
  vt_init(&masn);
  // Inserting keys and values.
  for( int i = 0; i < 10; ++i )
  {
    struct ipv4_asn k;
    k.addr = i;
    k.asn = i*2;
    ipv4asn_uint32_map_itr itr =
      vt_insert( &masn, k, i + 1 );
    if( vt_is_end( itr ) )
    {
      // Out of memory, so abort.
      vt_cleanup( &masn );
      return;
    }
  }

  // Erasing keys and values.
  for( int i = 0; i < 10; i += 3 ){
    struct ipv4_asn key;
    key.addr = i;
    key.asn = 2*i;
    vt_erase( &masn, key );
  }

  // Retrieving keys and values.
  for( int i = 0; i < 10; ++i )
  {
    struct ipv4_asn key;
    key.addr = i;
    key.asn = 2*i;
    ipv4asn_uint32_map_itr itr = vt_get( &masn, key );
    if( !vt_is_end( itr ) ){
      printf(
        "%u,%u:%d ",
        itr.data->key.addr,
        itr.data->key.asn,
        itr.data->val
      );
    }
    else{
      printf("can't find");
    }
  }
  // Printed: 1:2 2:3 4:5 5:6 7:8 8:9

  vt_cleanup( &masn );
    
    // wideArray_remove_test();
    // announce_cnt_insert_test();
    // announce_cnt_remove_test();
    // decoder_v6_test();
    // compressed_trie_test();
}

void test_diy(){
    uint32_t bm = calculate_bitmap(0,1,4);
    binary_print(bm);
    // struct rov_algo_t *algo;
    // algo = (struct rov_algo_t *)malloc(sizeof(struct rov_algo_t));
    // algo->ht = NULL;
    // COPY_ALGO(algo,bird);
    // // COPY_ALGO(algo,trov);

    // algo->test_data_coding = mrov_coding_rd;
    // algo->files.pdu_file = "./test_data/exp_all_rrc/v4/vrp_rib.txt";
    // // algo->files.upd_wth_file = "./test_data/huawei/2023.0301_vrp_v6.txt";
    // algo->files.validate_file = "./test_data/exp_all_rrc/v4/updates/rrc00.txt";
    // // algo->files.validate_file = "./test_data/hrov_rd/h_update_v4.txt";
    // algo->result_file = "./test_data/test_result/hbasic/v4/result.txt";

    // if(rov_init(algo)!=SUCCESS){
    //     LOG_ERROR("rov init");
    // }

    // FILE * fptr;
    // ssize_t read;
    // char * line = NULL;
    // size_t len = 0;
    // fptr = fopen(algo->files.pdu_file,"r");

    // while ((read = getline(&line, &len, fptr)) != -1) {
    //     // puts(line);
    //     void * pdu = mrov_coding_rd(line);
    //     algo->rov_pfx_add(algo->ht,pdu);
    //     // h_pfxt_print_binary(algo);
    //     // puts("============");
    // }
    // free(line);
    // fclose(fptr);
    
    // LOG_SUCCESS("basic_building");

    // // hrov_table_basic_print(algo->ht);
    // // h_pfxt_print_nlbs(algo);
    // // h_pfxt_print_basic(algo);
    // // h_pfxt_print_binary(algo);

    // // if(withdrawn(algo)!=SUCCESS){
    // //     LOG_ERROR("withdrawn");
    // // }

    // // h_pfxt_print_nlbs(algo);
    // // h_pfxt_print_binary(algo);
    // // h_pfxt_print_basic(algo);
    
    // // if(insert(algo)!=SUCCESS){
    // //     LOG_ERROR("insert");
    // // }

    // // h_pfxt_print_basic(algo);

    // if(validate(algo)!=SUCCESS){
    //     LOG_ERROR("validate");
    // }

    // if(mem_check(algo)!=SUCCESS){
    //     LOG_ERROR("mem_check");
    // }

    // if(release(algo)!=SUCCESS){
    //     LOG_ERROR("release");
    // }
  
    return;
}